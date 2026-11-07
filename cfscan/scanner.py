"""Scan orchestration.

Range scan:  Discovery (sample every /24) -> Expansion (dig into the fastest live
             /24s) -> Verify (re-test the best IPs N times: median, jitter, loss)
             -> Speed (real download through the best stable IPs).
List check:  Check (N rounds per given IP) -> Speed.
"""
from __future__ import annotations

import asyncio
import heapq
import random
import signal
import time
from collections import deque

from cfscan.engine import STAGES, Hit
from cfscan.ranges import host_offsets, int_to_ip

SPEED_GIVE_UP = 3  # consecutive failures with no success -> speed host unreachable


def score(h: Hit) -> float:
    """Lower is better (milliseconds-like): latency + jitter + loss + slow-download cost.

    The download term is 300 / (Mbps + 1): ~120 at 1.5 Mbps, ~30 at 9 Mbps, ~7 at 40 Mbps,
    so a throttled IP can't win on a fast handshake alone.
    """
    s = h.latency + 1.5 * (h.jitter or 0)
    if h.loss:
        s += 1000 * h.loss
    if h.speed is not None:
        s += 300 / (h.speed + 1)
    return s


def rank_key(h: Hit):
    """Verified & alive first; inside that: download-tested OK, then untested, then failed download."""
    if h.loss is None:
        group = 1
    elif h.loss >= 1:
        group = 2
    else:
        group = 0
    tier = 0 if h.speed is not None else 2 if h.speed_err and h.speed_err != "skipped" else 1
    return (group, tier, score(h))


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
        self.fails = dict.fromkeys(STAGES, 0)
        self.hits = {}
        self.logs = deque(maxlen=200)
        self.log_seq = 0
        self.sink = None
        self.stopping = False
        self.skip = False
        self.speed_tested = 0
        self.speed_ok = 0
        self.speed_blocked = ""
        self.rate = 0.0
        self._samples = deque(maxlen=24)
        self._start = time.monotonic()
        self._end = None

    # ---- events ----
    def log(self, message, level="info"):
        self.logs.append((time.strftime("%H:%M:%S"), message, level))
        self.log_seq += 1

    def begin_phase(self, name, total):
        self.phase, self.phase_total, self.phase_done = name, total, 0
        self.skip = False
        self._samples.clear()
        self.rate = 0.0
        self.log(f"{name}: {total:,} checks")

    def add_fail(self, stage):
        self.fails[stage] = self.fails.get(stage, 0) + 1

    def add_hit(self, hit):
        if self.colos and hit.colo != "-" and hit.colo.upper() not in self.colos:
            self.filtered += 1
            return False
        self.hits[hit.ip] = hit
        self.found += 1
        if self.sink is not None:
            self.sink.add(hit)
        return True

    def record(self, hit, stage):
        self.tested += 1
        self.phase_done += 1
        if hit is None:
            self.add_fail(stage)
            return False
        return self.add_hit(hit)

    # ---- timing ----
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

    @property
    def done(self):
        return self._end is not None

    def finish(self):
        if self._end is None:
            self._end = time.monotonic()
            self.phase = "Stopped" if self.stopping else "Done"
            self.log("Stopped by user" if self.stopping else "Finished", "good")

    # ---- results ----
    def top(self, n):
        return heapq.nsmallest(n, self.hits.values(), key=rank_key)

    def ranked(self):
        return sorted(self.hits.values(), key=rank_key)


class Scanner:
    def __init__(self, cfg, prober, state, blocks=(), targets=None, speed=None):
        self.cfg = cfg
        self.prober = prober
        self.state = state
        self.blocks = list(blocks)
        self.targets = targets   # list of IPs -> list-check mode
        self.speed = speed       # SpeedTester or None
        self._task = None
        self._rng = random.Random(cfg.get("seed"))

    # ---------- lifecycle ----------

    async def run(self, ui=None):
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _loop, _ctx: None)  # aborted TLS noise
        self._task = asyncio.current_task()
        try:
            loop.add_signal_handler(signal.SIGINT, self.request_stop)
        except (NotImplementedError, RuntimeError, ValueError, AttributeError):
            pass  # Windows: Ctrl+C arrives as KeyboardInterrupt instead

        ui_task = asyncio.ensure_future(self._ui_loop(ui)) if ui is not None else None
        try:
            await self._scan()
        except asyncio.CancelledError:
            self.state.stopping = True
        finally:
            if ui_task is not None:
                ui_task.cancel()
            self.state.finish()
            if ui is not None:
                ui.refresh()

    def request_stop(self):
        st = self.state
        if st.stopping:
            if self._task is not None:
                self._task.cancel()  # second request: quit now
        else:
            st.stopping = True
            st.log("Stopping - finishing open checks (press again to quit now)", "warn")

    def request_skip(self):
        if not self.state.stopping and not self.state.done:
            self.state.skip = True
            self.state.log(f"Skipping the rest of {self.state.phase}", "warn")

    async def _ui_loop(self, ui):
        while True:
            self.state.tick()
            for key in ui.keys():
                if key in ("q", "Q", "\x1b"):
                    self.request_stop()
                elif key in ("n", "N", "s", "S"):
                    self.request_skip()
            ui.refresh()
            await asyncio.sleep(0.2)

    def _target_reached(self):
        target = self.cfg.get("target", 0)
        return target > 0 and self.state.found >= target

    def _halt(self, discovery=False):
        st = self.state
        return st.stopping or st.skip or (discovery and self._target_reached())

    # ---------- phases ----------

    async def _scan(self):
        c, st = self.cfg, self.state
        do_speed = self.speed is not None and c.get("speed_top", 0) > 0

        if self.targets is not None:
            st.phases = ["Check"] + (["Speed"] if do_speed else [])
            await self._check_list()
            if do_speed and not st.stopping:
                await self._speed()
            return

        full = c["sample"] <= 0
        expand = not full and c["expand_blocks"] > 0 and c["expand"] > 0
        phases = ["Scan"] if full else ["Discovery"]
        if expand:
            phases.append("Expansion")
        if c["verify_top"] > 0:
            phases.append("Verify")
        if do_speed:
            phases.append("Speed")
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
            st.log(f"{len(live_blocks):,} of {len(self.blocks):,} /24 blocks answered", "good")
            if expand and not st.stopping:
                if self._target_reached():
                    st.log("Target reached - skipping expansion")
                elif live_blocks:
                    order = sorted(live_blocks, key=live_blocks.get)[: c["expand_blocks"]]
                    await self._probe_phase("Expansion", *self._plan_expand(order, tested), on_hit)

        if "Verify" in phases and not st.stopping:
            await self._verify()
        if do_speed and not st.stopping:
            await self._speed()

    def _plan_sample(self, tested):
        k = self.cfg["sample"]
        order = list(range(len(self.blocks)))
        self._rng.shuffle(order)
        total = sum(min(k, len(host_offsets(self.blocks[i][1]))) for i in order)

        def gen():
            for idx in order:
                base, size = self.blocks[idx]
                offs = host_offsets(size)
                pick = self._rng.sample(offs, min(k, len(offs)))
                tested[idx] = set(pick)
                for o in pick:
                    yield idx, base + o

        return gen(), total

    def _plan_full(self):
        order = list(range(len(self.blocks)))
        self._rng.shuffle(order)
        total = sum(len(host_offsets(self.blocks[i][1])) for i in order)

        def gen():
            for idx in order:
                base, size = self.blocks[idx]
                offs = list(host_offsets(size))
                self._rng.shuffle(offs)
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
            self._rng.shuffle(rest)
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
        if total == 0 or self._halt(True):
            return
        it = iter(items)  # shared by all workers; safe: single-threaded

        async def worker():
            for idx, ip_int in it:
                if self._halt(True):
                    return
                hit, stage = await self.prober.probe(int_to_ip(ip_int))
                if st.record(hit, stage):
                    on_hit(idx, hit)

        await asyncio.gather(*(worker() for _ in range(min(self.cfg["concurrency"], total))))

    async def _rounds(self, ip, rounds):
        """Probes one IP `rounds` times. Returns (first_hit, tcps, tlss, last_stage, done)."""
        st = self.state
        first, tcps, tlss, last, done = None, [], [], "tcp", 0
        for i in range(rounds):
            if self._halt():
                break
            hit, stage = await self.prober.probe(ip)
            st.phase_done += 1
            done += 1
            if hit is not None:
                first = first or hit
                tcps.append(hit.tcp)
                tlss.append(hit.tls)
            else:
                last = stage
            if i + 1 < rounds:
                await asyncio.sleep(0.05)
        return first, tcps, tlss, last, done

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
                if self._halt():
                    return
                _, tcps, tlss, _, done = await self._rounds(hit.ip, rounds)
                if done:
                    hit.apply_rounds(tcps, tlss, done)

        await asyncio.gather(*(worker() for _ in range(min(32, c["concurrency"], len(candidates)))))
        checked = [h for h in candidates if h.verified]
        stable = sum(1 for h in checked if h.loss == 0)
        st.log(f"Verified {len(checked)} IPs - {stable} with zero loss", "good")

    async def _check_list(self):
        st, c = self.state, self.cfg
        rounds = max(1, c["verify_rounds"])
        st.begin_phase("Check", len(self.targets) * rounds)
        it = iter(self.targets)

        async def worker():
            for ip in it:
                if self._halt():
                    return
                first, tcps, tlss, last, done = await self._rounds(ip, rounds)
                if not done:
                    return
                st.tested += 1
                if first is None:
                    st.add_fail(last)
                    continue
                first.apply_rounds(tcps, tlss, done)
                st.add_hit(first)

        await asyncio.gather(*(worker() for _ in range(min(64, c["concurrency"], len(self.targets)))))
        st.log(f"{st.found} of {st.tested} IPs passed", "good" if st.found else "warn")

    async def _speed(self):
        st, c = self.state, self.cfg
        pool = [h for h in st.ranked() if h.alive]
        candidates = pool[: c["speed_top"]]
        if not candidates:
            return
        st.begin_phase("Speed", len(candidates))
        st.log(f"Download test via {self.speed.host}")
        it = iter(candidates)
        streak = {"fail": 0, "last": ""}

        async def worker():
            for hit in it:
                if self._halt() or st.speed_blocked:
                    return
                mbps, err = await self.speed.run(hit.ip)
                st.phase_done += 1
                st.speed_tested += 1
                if mbps is not None:
                    hit.speed, hit.speed_err = round(mbps, 1), ""
                    st.speed_ok += 1
                    streak["fail"] = 0
                else:
                    hit.speed, hit.speed_err = None, err or "failed"
                    streak["fail"] += 1
                    streak["last"] = hit.speed_err
                    if st.speed_ok == 0 and streak["fail"] >= SPEED_GIVE_UP:
                        st.speed_blocked = streak["last"]
                        for h in candidates:
                            if h.speed is None and not h.speed_err:
                                h.speed_err = "skipped"
                        st.log(f"Speed host unreachable ({streak['last']}) - speed test skipped", "warn")
                        return

        await asyncio.gather(*(worker() for _ in range(max(1, min(c.get("speed_par", 1), len(candidates))))))
        if st.speed_blocked:
            # Unreachable speed host says nothing about the IPs: don't penalise them.
            for h in candidates:
                h.speed_err = ""
        elif st.speed_ok:
            best = max(h.speed for h in candidates if h.speed is not None)
            st.log(f"Speed: {st.speed_ok}/{st.speed_tested} OK, best {best:.1f} Mbps", "good")
