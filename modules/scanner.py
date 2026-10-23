"""Scan orchestration: discovery -> expansion -> verification."""
import asyncio
import heapq
import random
import signal
import time
from collections import deque
from statistics import median

from modules.ranges import host_offsets, int_to_ip

FAIL_KEYS = ("tcp", "tls", "cert", "http")


def rank_key(hit):
    """Stable verified IPs first, then unverified, then IPs that failed every re-test."""
    if hit.loss is None:
        group = 1
    elif hit.loss >= 1:
        group = 2
    else:
        group = 0
    latency = hit.median if hit.median is not None else hit.tls
    return (group, hit.loss or 0, latency)


class ScanState:
    """Everything the UI shows. Only touched from the event-loop thread."""

    def __init__(self, colos=()):
        self.colos = {c.upper() for c in colos}
        self.phases = []
        self.phase = "Starting"
        self.phase_total = 0
        self.phase_done = 0
        self.tested = 0
        self.found = 0
        self.filtered = 0
        self.live_blocks = 0
        self.fails = dict.fromkeys(FAIL_KEYS, 0)
        self.hits = {}
        self.logs = deque(maxlen=50)
        self.sink = None
        self.stopping = False
        self.rate = 0.0
        self._samples = deque(maxlen=20)
        self._start = time.monotonic()
        self._end = None

    def log(self, message):
        self.logs.append((time.strftime("%H:%M:%S"), message))

    def begin_phase(self, name, total):
        self.phase, self.phase_total, self.phase_done = name, total, 0
        self._samples.clear()
        self.rate = 0.0
        self.log(f"{name} started - {total:,} checks")

    def record(self, ip, hit, stage):
        self.tested += 1
        self.phase_done += 1
        if hit is None:
            self.fails[stage] = self.fails.get(stage, 0) + 1
            return None
        if self.colos and hit.colo != "-" and hit.colo.upper() not in self.colos:
            self.filtered += 1
            return None
        self.hits[ip] = hit
        self.found += 1
        if self.sink is not None:
            self.sink.add(hit)
        return hit

    def tick(self):
        now = time.monotonic()
        self._samples.append((now, self.phase_done))
        t0, d0 = self._samples[0]
        if now - t0 >= 0.5:
            self.rate = (self.phase_done - d0) / (now - t0)

    def eta(self):
        left = self.phase_total - self.phase_done
        if self._end is not None or self.rate <= 0 or left <= 0:
            return None
        return left / self.rate

    def elapsed(self):
        return (self._end or time.monotonic()) - self._start

    def finish(self):
        if self._end is None:
            self._end = time.monotonic()
            self.phase = "Stopped" if self.stopping else "Done"
            self.log("Scan stopped by user" if self.stopping else "Scan finished")

    def top(self, n):
        return heapq.nsmallest(n, self.hits.values(), key=rank_key)

    def ranked(self):
        return sorted(self.hits.values(), key=rank_key)


class Scanner:
    def __init__(self, cfg, blocks, prober, state):
        self.cfg = cfg
        self.blocks = blocks
        self.prober = prober
        self.state = state
        self._task = None

    # ---------- lifecycle ----------

    async def run(self, live):
        loop = asyncio.get_running_loop()
        # Aborted TLS connections produce harmless but noisy loop errors.
        loop.set_exception_handler(lambda _loop, _context: None)
        self._task = asyncio.current_task()
        try:
            loop.add_signal_handler(signal.SIGINT, self._on_sigint)
        except (NotImplementedError, RuntimeError, ValueError):
            pass  # Windows: Ctrl+C raises KeyboardInterrupt instead

        ui = asyncio.ensure_future(self._ui_loop(live))
        try:
            await self._scan()
        except asyncio.CancelledError:
            self.state.stopping = True
            raise
        finally:
            ui.cancel()
            self.state.finish()
            live.refresh()

    def _on_sigint(self):
        if self.state.stopping:
            self._task.cancel()  # second Ctrl+C: quit now
        else:
            self.state.stopping = True
            self.state.log("Stopping - finishing open checks (Ctrl+C again to quit now)")

    async def _ui_loop(self, live):
        while True:
            self.state.tick()
            live.refresh()
            await asyncio.sleep(0.25)

    def _enough(self):
        target = self.cfg["target"]
        return target > 0 and self.state.found >= target

    def _halt(self):
        return self.state.stopping or self._enough()

    # ---------- phases ----------

    async def _scan(self):
        c, st = self.cfg, self.state
        full = c["sample"] <= 0
        phases = ["Scan"] if full else ["Discovery"]
        if not full and c["expand"] > 0:
            phases.append("Expansion")
        if c["verify_top"] > 0:
            phases.append("Verify")
        st.phases = phases

        tested = {}       # block index -> offsets already probed
        live_blocks = {}  # block index -> best TLS latency seen

        def on_hit(idx, hit):
            best = live_blocks.get(idx)
            if best is None or hit.tls < best:
                live_blocks[idx] = hit.tls
            st.live_blocks = len(live_blocks)

        if full:
            await self._probe_phase("Scan", *self._plan_full(), on_hit)
        else:
            await self._probe_phase("Discovery", *self._plan_sample(tested), on_hit)
            st.log(f"{len(live_blocks):,} of {len(self.blocks):,} /24 blocks responded")
            if "Expansion" in phases and not st.stopping:
                if self._enough():
                    st.log("Target reached - skipping expansion")
                elif live_blocks:
                    order = sorted(live_blocks, key=live_blocks.get)  # fastest blocks first
                    await self._probe_phase("Expansion", *self._plan_expand(order, tested), on_hit)

        if "Verify" in phases and not st.stopping:
            await self._verify()

    def _plan_sample(self, tested):
        k = self.cfg["sample"]
        order = list(range(len(self.blocks)))
        random.shuffle(order)
        total = sum(min(k, len(host_offsets(self.blocks[i][1]))) for i in order)

        def gen():
            for idx in order:
                base, size = self.blocks[idx]
                offs = host_offsets(size)
                pick = random.sample(offs, min(k, len(offs)))
                tested[idx] = set(pick)
                for o in pick:
                    yield idx, base + o

        return gen(), total

    def _plan_full(self):
        order = list(range(len(self.blocks)))
        random.shuffle(order)
        total = sum(len(host_offsets(self.blocks[i][1])) for i in order)

        def gen():
            for idx in order:
                base, size = self.blocks[idx]
                offs = list(host_offsets(size))
                random.shuffle(offs)
                for o in offs:
                    yield idx, base + o

        return gen(), total

    def _plan_expand(self, order, tested):
        n = self.cfg["expand"]
        plan = []
        for idx in order:
            base, size = self.blocks[idx]
            done = tested.get(idx, ())
            rest = [o for o in host_offsets(size) if o not in done]
            random.shuffle(rest)
            plan.append((idx, base, rest[:n]))
        total = sum(len(p[2]) for p in plan)

        def gen():
            for idx, base, offs in plan:
                for o in offs:
                    yield idx, base + o

        return gen(), total

    async def _probe_phase(self, name, items, total, on_hit):
        st = self.state
        st.begin_phase(name, total)
        if total == 0 or self._halt():
            return
        it = iter(items)  # shared by all workers; safe because it's single-threaded

        async def worker():
            for idx, ip_int in it:
                if self._halt():
                    return
                ip = int_to_ip(ip_int)
                hit, stage = await self.prober.probe(ip)
                st.record(ip, hit, stage)
                if hit is not None:
                    on_hit(idx, hit)

        workers = min(self.cfg["concurrency"], total)
        await asyncio.gather(*(worker() for _ in range(workers)))

    async def _verify(self):
        st, c = self.state, self.cfg
        candidates = heapq.nsmallest(c["verify_top"], st.hits.values(), key=lambda h: h.tls)
        if not candidates:
            return
        rounds = max(1, c["verify_rounds"])
        st.begin_phase("Verify", len(candidates) * rounds)
        it = iter(candidates)

        async def worker():
            for hit in it:
                if st.stopping:
                    return
                latencies = []
                for _ in range(rounds):
                    result, _stage = await self.prober.probe(hit.ip)
                    st.phase_done += 1
                    if result is not None:
                        latencies.append(result.tls)
                    await asyncio.sleep(0.05)
                hit.loss = 1 - len(latencies) / rounds
                hit.median = int(median(latencies)) if latencies else None

        workers = min(32, c["concurrency"], len(candidates))
        await asyncio.gather(*(worker() for _ in range(workers)))
        stable = sum(1 for h in candidates if h.loss == 0)
        st.log(f"Verified {len(candidates)} IPs - {stable} with zero loss")
