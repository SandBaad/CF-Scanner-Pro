"""Text UI: building blocks, the live dashboard, the plain progress line and the summary."""
from __future__ import annotations

import shutil
import textwrap
import sys
import time

from cfscan import APP_NAME, __version__
from cfscan.colos import city

FAILS = (("tcp", "TCP", "bad"), ("tls", "TLS", "magenta"), ("cert", "Cert", "warn"), ("http", "HTTP", "info"))
HINTS = {
    "tcp": "No IP accepted a TCP connection. Check your connection, try another --port, or raise --timeout.",
    "tls": "TCP works but TLS handshakes fail - the SNI is probably filtered. Try another domain.",
    "cert": "Certificates don't match the SNI: is the domain really on Cloudflare? The connection "
            "may also be intercepted. --insecure skips the check.",
    "http": "Handshakes work but /cdn-cgi/trace fails. Make sure the domain is proxied (orange cloud), "
            "or use --no-http.",
}


def rate_str(r):
    return f"{r:,.0f}/s" if r >= 10 else f"{r:.1f}/s"


def hms(seconds):
    if seconds is None:
        return "--:--"
    s = int(seconds)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60:02d}:{s % 60:02d}"


# ---------------------------------------------------------------- primitives

class Line:
    """A row of styled text pieces with a known visible width."""
    __slots__ = ("parts",)

    def __init__(self, *parts):
        self.parts = []
        for p in parts:
            if isinstance(p, tuple):
                self.add(*p)
            else:
                self.add(p)

    def add(self, text, style=None):
        self.parts.append((str(text), style))
        return self

    def extend(self, other):
        self.parts.extend(other.parts)
        return self

    def __len__(self):
        return sum(len(t) for t, _ in self.parts)

    def plain(self):
        return "".join(t for t, _ in self.parts)

    def render(self, th, width, pad=True):
        out, used = [], 0
        for text, style in self.parts:
            room = width - used
            if room <= 0:
                break
            if len(text) > room:
                text = text[: room - 1] + th.ell if room > 1 else th.ell
            out.append(th.paint(text, style))
            used += len(text)
        if pad and used < width:
            out.append(" " * (width - used))
        return "".join(out)


def kv(label, value, width, vstyle="bold", lstyle="dim"):
    value = str(value)
    gap = max(1, width - len(label) - len(value))
    return Line((label, lstyle), (" " * gap, None), (value, vstyle))


def center(text, width, style=None):
    left = max(0, (width - len(text)) // 2)
    return Line((" " * left, None), (text, style))


def box(th, title, lines, width, height=None, border="border", title_style="title", right=""):
    """Rounded panel. `height` includes the borders; content is cut or padded to fit."""
    inner = width - 4
    title = f" {title} " if title else ""
    right = f" {right} " if right else ""
    fill = width - 2 - 1 - len(title) - len(right) - 1
    if fill < 0:
        title, right, fill = "", "", width - 2
        top = th.paint(th.tl + th.h * fill + th.tr, border)
    else:
        top = (th.paint(th.tl + th.h, border) + th.paint(title, title_style)
               + th.paint(th.h * fill, border) + th.paint(right, "dim") + th.paint(th.h + th.tr, border))
    rows = list(lines)
    if height is not None:
        body = max(0, height - 2)
        rows = rows[:body] + [Line()] * (body - len(rows[:body]))
    v = th.paint(th.v, border)
    out = [top]
    out += [f"{v} {ln.render(th, inner)} {v}" for ln in rows]
    out.append(th.paint(th.bl + th.h * (width - 2) + th.br, border))
    return out


def hjoin(left, right, lw, rw, gap=1):
    n = max(len(left), len(right))
    left = left + [" " * lw] * (n - len(left))
    right = right + [" " * rw] * (n - len(right))
    return [a + " " * gap + b for a, b in zip(left, right)]


def bar_line(th, frac, width, style="accent"):
    frac = min(max(frac, 0.0), 1.0)
    filled = int(round(frac * width))
    return Line((th.bar * filled, "good" if frac >= 1 else style), (th.bar_empty * (width - filled), "muted"))


# ---------------------------------------------------------------- result table

def lat_cell(th, ms):
    if ms is None:
        return (th.pending, "muted")
    return (f"{ms}", "goodb" if ms < 150 else "good" if ms < 250 else "warn" if ms < 450 else "bad")


def loss_cell(th, h):
    if h.loss is None:
        return (th.pending, "muted")
    pct = round(h.loss * 100)
    return (f"{pct}%", "good" if pct == 0 else "warn" if pct < 34 else "bad")


def jitter_cell(th, h):
    if h.jitter is None:
        return (th.pending, "muted")
    return (f"{h.jitter}", "good" if h.jitter < 20 else "warn" if h.jitter < 60 else "bad")


def speed_cell(th, h):
    if h.speed is not None:
        return (f"{h.speed:.1f}", "goodb" if h.speed >= 20 else "good" if h.speed >= 8 else "warn" if h.speed >= 2 else "bad")
    if h.speed_err and h.speed_err != "skipped":
        return (th.cross, "bad")
    return (th.pending, "muted") if not h.verified else (th.dash, "muted")


COLUMNS = {
    #  key      header    min  align
    "rank": ("#", 3, ">"),
    "ip": ("IP", 15, "<"),
    "ping": ("Ping", 4, ">"),
    "tls": ("TLS", 4, ">"),
    "jitter": ("Jit", 3, ">"),
    "loss": ("Loss", 4, ">"),
    "speed": ("Mbps", 5, ">"),
    "colo": ("Colo", 4, "<"),
    "city": ("City", 4, "<"),
}
WIDE_COLS = ("rank", "ip", "ping", "tls", "jitter", "loss", "speed", "colo", "city")
NARROW_COLS = ("rank", "ip", "tls", "loss", "speed", "colo")
TINY_COLS = ("ip", "tls", "loss", "colo")


def hit_cells(th, i, h, cols):
    cell = {
        "rank": lambda: (str(i), "dim"),
        "ip": lambda: (h.ip, "ip"),
        "ping": lambda: lat_cell(th, h.ping if h.ping is not None else h.tcp),
        "tls": lambda: lat_cell(th, h.latency),
        "jitter": lambda: jitter_cell(th, h),
        "loss": lambda: loss_cell(th, h),
        "speed": lambda: speed_cell(th, h),
        "colo": lambda: (h.colo, "colo"),
        "city": lambda: (city(h.colo), "dim"),
    }
    return [cell[c]() for c in cols]


def pick_cols(width):
    for cols in (WIDE_COLS, NARROW_COLS, TINY_COLS):
        need = sum(max(COLUMNS[c][1], len(COLUMNS[c][0])) for c in cols) + 2 * (len(cols) - 1)
        if cols is WIDE_COLS:
            need += 8  # leave room for city names
        if need <= width:
            return cols
    return TINY_COLS


def hit_table(th, hits, width, cols=None):
    cols = cols or pick_cols(width)
    rows = [hit_cells(th, i, h, cols) for i, h in enumerate(hits, 1)]
    widths = []
    for k, c in enumerate(cols):
        header, mn, _ = COLUMNS[c]
        widths.append(max([mn, len(header)] + [len(r[k][0]) for r in rows]))
    # Last text column takes whatever is left (and gets truncated if needed).
    used = sum(widths[:-1]) + 2 * (len(cols) - 1)
    widths[-1] = max(1, width - used)

    def fmt(cells):
        line = Line()
        for k, (text, style) in enumerate(cells):
            w, align = widths[k], COLUMNS[cols[k]][2]
            if len(text) > w:
                text = text[: max(w - 1, 0)] + th.ell
            pad = " " * (w - len(text))
            if align == ">":
                line.add(pad).add(text, style)
            else:
                line.add(text, style).add(pad)
            if k < len(cells) - 1:
                line.add("  ")
        return line

    out = [fmt([(COLUMNS[c][0], "head") for c in cols]), Line((th.h * width, "muted"))]
    out += [fmt(r) for r in rows]
    return out


# ---------------------------------------------------------------- dashboard

class Dashboard:
    def __init__(self, state, cfg, th, live_path=""):
        self.state = state
        self.cfg = cfg
        self.th = th
        self.live_path = live_path

    def render(self, width, height):
        width, height = max(width, 44), max(height, 14)
        compact = width < 100
        out = self._header(width, compact)
        show_log = height >= 24
        log_n = (3 if compact else 4) if show_log else 0
        body_h = height - len(out) - (log_n + 2 if show_log else 0) - 1
        if compact:
            stats = box(self.th, "", self._stats_compact(width - 4), width, border="frame")
            out += stats
            out += self._best(width, max(body_h - len(stats), 5))
        else:
            sw = 34
            body_h = max(body_h, 8)
            out += hjoin(self._stats(sw, body_h), self._best(width - sw - 1, body_h), sw, width - sw - 1)
        if show_log:
            out += self._log(width, log_n)
        out.append(self._footer(width))
        return out[:height]

    # ---- pieces ----
    def _phase_line(self):
        th, s = self.th, self.state
        line = Line()
        cur = s.phases.index(s.phase) if s.phase in s.phases else (len(s.phases) if s.done else -1)
        for i, name in enumerate(s.phases):
            if i:
                line.add(f"  {th.dot}  ", "muted")
            if i < cur or (s.done and s.phase == "Done"):
                line.add(f"{th.done} {name}", "good")
            elif i == cur:
                line.add(f"{th.cur} {name}", "title")
            else:
                line.add(f"{th.todo} {name}", "dim")
        if s.done:
            line.add("   ")
            line.add(" STOPPED " if s.stopping else " DONE ", "keyw" if s.stopping else "key")
        return line

    def _header(self, width, compact):
        th, s, c = self.th, self.state, self.cfg
        inner = width - 4
        title = Line((f"{APP_NAME}", "title"), (f" v{__version__}", "dim"), ("   ", None), (c["sni"], "ip"))
        if not compact:
            mode = c.get("mode", "list")
            title.add(f"   {mode.title()} {th.dot} {c['concurrency']} conns {th.dot} "
                      f"{c['timeout']:g}s {th.dot} port {c['port']}", "dim")
        pct = s.phase_done / s.phase_total if s.phase_total else (1.0 if s.done else 0.0)
        if compact:
            info = f" {pct:4.0%}  {rate_str(s.rate)}  ETA {hms(s.eta())}"
        else:
            info = (f" {pct:4.0%}  {s.phase_done:,}/{s.phase_total:,}  {th.dot}  "
                    f"{rate_str(s.rate)}  {th.dot}  ETA {hms(s.eta())}")
        bar = bar_line(th, pct, max(8, inner - len(info)))
        bar.add(info, "accent2")
        return box(th, "", [title, self._phase_line(), bar], width)

    def _fail_lines(self, inner, barw):
        th, s = self.th, self.state
        total = max(1, sum(s.fails.values()) + s.found)
        lines = []
        for key, label, color in FAILS:
            n = s.fails.get(key, 0)
            filled = round(barw * n / total)
            ln = Line((f"{label:<5}", "dim"), (th.bar * filled, color), (th.bar_empty * (barw - filled), "muted"))
            val = f"{n:,}"
            ln.add(" " * max(1, inner - 5 - barw - len(val))).add(val, "text")
            lines.append(ln)
        return lines

    def _stats(self, width, height):
        s, inner = self.state, width - 4
        lines = [
            kv("Tested", f"{s.tested:,}", inner),
            kv("Working", f"{s.found:,}", inner, "goodb"),
        ]
        if s.colos:
            lines.append(kv("Other colos", f"{s.filtered:,}", inner, "dim"))
        if s.phases and s.phases[0] != "Check":
            lines.append(kv("Live /24", f"{s.live_blocks:,}", inner))
        lines += [kv("Rate", rate_str(s.rate), inner, "accent2"), kv("Elapsed", hms(s.elapsed()), inner, "text")]
        if s.speed_tested:
            lines.append(kv("Speed OK", f"{s.speed_ok}/{s.speed_tested}", inner, "good" if s.speed_ok else "warn"))
        lines += [Line(), Line(("Failures", "bold"))] + self._fail_lines(inner, inner - 12)
        return box(self.th, "Stats", lines, width, height)

    def _stats_compact(self, inner):
        th, s = self.th, self.state
        l1 = Line(("Tested ", "dim"), (f"{s.tested:,}", "bold"), ("  Working ", "dim"), (f"{s.found:,}", "goodb"),
                  ("  ", None), (hms(s.elapsed()), "text"))
        l2 = Line(("Fail ", "dim"))
        for key, label, color in FAILS:
            l2.add(f"{label} ", "dim").add(f"{s.fails.get(key, 0):,}", color).add("  ")
        return [l1, l2]

    def _best(self, width, height):
        th, s = self.th, self.state
        inner = width - 4
        rows = max(1, height - 4)
        hits = s.top(rows)
        if hits:
            lines = hit_table(th, hits, inner)
        else:
            msg = "Searching for working IPs..." if not s.done else "No working IPs found"
            lines = [Line()] * max(0, (height - 3) // 2) + [center(msg, inner, "dim")]
        return box(th, "Best IPs", lines, width, height, border="border", right=f"{s.found:,} working")

    def _log(self, width, n):
        th = self.th
        lines = []
        for ts, msg, level in list(self.state.logs)[-n:]:
            style = {"warn": "warn", "good": "good", "bad": "bad"}.get(level, "text")
            lines.append(Line((ts + "  ", "muted"), (msg, style)))
        return box(th, "Log", lines, width, n + 2, border="frame", title_style="dim")

    def _footer(self, width):
        th, s = self.th, self.state
        if s.done:
            ln = Line((" Finished ", "key"), ("  writing results...", "dim"))
        elif s.stopping:
            ln = Line((" q ", "keyw"), ("  stopping... press again to quit now", "warn"))
        else:
            ln = Line((" q ", "key"), (" stop & save   ", "dim"), (" n ", "key"), (" next phase   ", "dim"))
            if self.live_path:
                ln.add(f"live {th.arrow} {self.live_path}", "muted")
        return ln.render(th, width)


class LiveUI:
    """Full-screen dashboard driver used by Scanner.run()."""

    def __init__(self, dashboard, screen, keys):
        self.dash = dashboard
        self.screen = screen
        self.keyreader = keys
        self._last = 0.0

    def keys(self):
        return self.keyreader.read()

    def refresh(self):
        size = shutil.get_terminal_size((100, 30))
        self.screen.draw(self.dash.render(size.columns - 1, size.lines))


class PlainUI:
    """One status line every few seconds - for pipes, logs, CI and --plain."""

    def __init__(self, state, th, stream=None, every=3.0, quiet=False):
        self.state = state
        self.th = th
        self.out = stream or sys.stderr
        self.every = every
        self.quiet = quiet
        self._last = 0.0
        self._logs = 0

    def keys(self):
        return []

    def refresh(self):
        if self.quiet:
            return
        s = self.state
        new = min(s.log_seq - self._logs, len(s.logs))
        if new > 0:
            for ts, msg, _ in list(s.logs)[-new:]:
                self.out.write(f"{ts}  {msg}\n")
        self._logs = s.log_seq
        now = time.monotonic()
        if now - self._last < self.every and not s.done:
            return
        self._last = now
        pct = s.phase_done / s.phase_total if s.phase_total else 0
        self.out.write(f"  [{s.phase}] {pct:4.0%}  {s.phase_done:,}/{s.phase_total:,}  "
                       f"{rate_str(s.rate)}  working {s.found:,}  ETA {hms(s.eta())}\n")
        self.out.flush()


# ---------------------------------------------------------------- summary

def diagnose(state, speed_label=""):
    s = state
    out = []
    if s.tested and s.found == 0:
        if s.filtered:
            out.append("Working IPs were found, but none in the colos you asked for (--colo).")
        else:
            worst = max(s.fails, key=s.fails.get)
            if s.fails[worst]:
                out.append(HINTS[worst])
    elif s.fails.get("cert"):
        out.append(f"{s.fails['cert']:,} IPs showed a certificate that doesn't match your SNI and were dropped.")
    if s.speed_blocked:
        out.append(f"Download test host was unreachable ({s.speed_blocked}) - {speed_label or 'it'} may be "
                   "filtered on your network. Use --speed-url https://your.domain/big-file or --no-speed.")
    return out


def render_summary(th, state, hits, width, saved=0, sink=None, speed_label="", title_note=""):
    width = max(44, min(width, 118))
    inner = width - 4
    s = state
    done = s.phase == "Done"
    lines = [Line(("Scan complete" if done else "Scan stopped",
                   "goodb" if done else "warn"),
                  (f"   {s.tested:,} tested {th.dot} {s.found:,} working {th.dot} {hms(s.elapsed())}", "dim"))]
    if title_note:
        lines.append(Line((title_note, "dim")))
    best = [h for h in hits if h.alive][:15]
    if best:
        lines.append(Line())
        lines += hit_table(th, best, inner)
    for hint in diagnose(s, speed_label):
        lines.append(Line())
        for k, part in enumerate(textwrap.wrap(hint, inner - 2)):
            lines.append(Line(("! " if k == 0 else "  ", "warn"), (part, "warn")))
    lines.append(Line())
    if saved and sink is not None:
        lines.append(Line(("Saved ", "dim"), (f"{saved} IPs", "goodb"), (f" {th.arrow} {sink.ips_path}", "text")))
        lines.append(Line(("Details ", "dim"), (f"{th.arrow} {sink.csv_path}, {sink.json_path}", "text")))
    elif not best:
        lines.append(Line(("No working IPs found.", "dim")))
    out = box(th, f"{APP_NAME} v{__version__}", lines, width, border="border" if done else "warn")
    if best:
        out.append("")
        out.append(th.paint("Top IPs (copy):", "dim"))
        out.append(", ".join(h.ip for h in best[:10]))
    return out
