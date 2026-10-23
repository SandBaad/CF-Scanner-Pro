"""Rich TUI: live dashboard and final summary."""
from rich import box
from rich.console import Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from modules import __version__

FAILS = (
    ("tcp", "TCP connect", "red"),
    ("tls", "TLS handshake", "magenta"),
    ("cert", "Cert mismatch", "yellow"),
    ("http", "HTTP check", "blue"),
)

HINTS = {
    "tcp": "No IP accepted a TCP connection. Check your internet connection or raise the timeout.",
    "tls": "TCP works but TLS handshakes fail - this usually means the SNI is filtered. Try another domain.",
    "cert": "Certificates don't match the SNI. Make sure the domain is on Cloudflare; "
            "the connection may also be intercepted.",
    "http": "Handshakes work but /cdn-cgi/trace fails. Make sure the domain is proxied "
            "(orange cloud), or disable the HTTP check.",
}


def hms(seconds):
    if seconds is None:
        return "--:--"
    s = int(seconds)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def lat_text(ms):
    if ms is None:
        return Text("—", style="dim")
    style = "bold green" if ms < 150 else "yellow" if ms < 300 else "red"
    return Text(f"{ms} ms", style=style)


def loss_text(loss):
    if loss is None:
        return Text("…", style="dim")
    pct = round(loss * 100)
    style = "green" if pct == 0 else "yellow" if pct < 50 else "red"
    return Text(f"{pct}%", style=style)


def results_table(hits, show_verify, compact):
    t = Table(box=box.SIMPLE_HEAD, expand=True, header_style="bold cyan",
              pad_edge=False, show_edge=False)
    t.add_column("#", justify="right", style="dim", width=3, no_wrap=True)
    t.add_column("IP", style="bold", no_wrap=True)
    t.add_column("TLS", justify="right", no_wrap=True)
    if not compact:
        t.add_column("TCP", justify="right", no_wrap=True)
    t.add_column("Colo", style="yellow", no_wrap=True)
    if show_verify:
        if not compact:
            t.add_column("Median", justify="right", no_wrap=True)
        t.add_column("Loss", justify="right", no_wrap=True)

    for i, h in enumerate(hits, 1):
        row = [str(i), h.ip, lat_text(h.tls)]
        if not compact:
            row.append(lat_text(h.tcp))
        row.append(h.colo)
        if show_verify:
            if not compact:
                row.append(lat_text(h.median))
            row.append(loss_text(h.loss))
        t.add_row(*row)
    return t


class Dashboard:
    """Full-screen live view; adapts to narrow terminals (e.g. Termux)."""

    def __init__(self, state, cfg):
        self.state = state
        self.cfg = cfg

    def __rich_console__(self, console, options):
        height = options.height or console.height
        compact = options.max_width < 96
        layout = Layout()
        header = Layout(self._header(compact), size=4)
        footer = Layout(self._footer(), size=1)

        if compact:
            log_lines = 3
            rows = max(3, height - (4 + 4 + log_lines + 2 + 1) - 4)
            layout.split_column(
                header,
                Layout(self._stats_compact(), size=4),
                Layout(self._best(rows, True)),
                Layout(self._log(log_lines), size=log_lines + 2),
                footer,
            )
        else:
            log_lines = 4
            rows = max(3, height - (4 + log_lines + 2 + 1) - 4)
            body = Layout()
            body.split_row(Layout(self._stats(), size=36), Layout(self._best(rows, False)))
            layout.split_column(header, body, Layout(self._log(log_lines), size=log_lines + 2), footer)
        yield layout

    # ---------- pieces ----------

    def _header(self, compact):
        s, c = self.state, self.cfg
        title = Text.assemble(("⚡ CF-Scanner Pro", "bold cyan"), ("  ", ""), (c["sni"], "bold white"),
                              no_wrap=True, overflow="ellipsis")
        if not compact:
            title.append(f"   {c['mode'].title()} mode · {c['concurrency']} conns · {c['timeout']}s timeout",
                         style="dim")

        if s.phase in s.phases:
            label = f"{s.phases.index(s.phase) + 1}/{len(s.phases)} {s.phase}"
        else:
            label = s.phase
        pct = s.phase_done / s.phase_total if s.phase_total else 0
        right = f"{pct:.0%}  ETA {hms(s.eta())}" if compact else \
            f"{pct:4.0%}  {s.phase_done:,}/{s.phase_total:,}  ETA {hms(s.eta())}"

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column(ratio=1)
        grid.add_column(no_wrap=True, justify="right")
        grid.add_row(
            Text(label, style="bold"),
            ProgressBar(total=max(s.phase_total, 1), completed=s.phase_done,
                        complete_style="cyan", finished_style="green"),
            Text(right, style="cyan"),
        )
        return Panel(Group(title, grid), box=box.ROUNDED, border_style="cyan", padding=(0, 1))

    def _stats(self):
        s = self.state
        g = Table.grid(padding=(0, 1), expand=True)
        g.add_column(style="dim", no_wrap=True)
        g.add_column(justify="right", no_wrap=True)
        g.add_row("Tested", Text(f"{s.tested:,}", style="bold"))
        g.add_row("Found", Text(f"{s.found:,}", style="bold green"))
        if s.colos:
            g.add_row("Other colos", f"{s.filtered:,}")
        g.add_row("Live /24 blocks", f"{s.live_blocks:,}")
        g.add_row("Speed", Text(f"{s.rate:,.0f} checks/s", style="cyan"))
        g.add_row("Elapsed", hms(s.elapsed()))

        f = Table.grid(padding=(0, 1), expand=True)
        f.add_column(no_wrap=True)
        f.add_column(no_wrap=True)
        f.add_column(justify="right", no_wrap=True)
        for key, label, color in FAILS:
            n = s.fails.get(key, 0)
            filled = round(10 * n / s.tested) if s.tested else 0
            bar = Text("━" * filled, style=color) + Text("━" * (10 - filled), style="grey30")
            f.add_row(Text(label, style="dim"), bar, f"{n:,}")

        return Panel(Group(g, Text(""), Text("Failures", style="bold"), f),
                     title="Stats", title_align="left", border_style="blue", box=box.ROUNDED)

    def _stats_compact(self):
        s = self.state
        line1 = Text.assemble(
            ("Tested ", "dim"), (f"{s.tested:,}", "bold"),
            ("  Found ", "dim"), (f"{s.found:,}", "bold green"),
            ("  ", ""), (f"{s.rate:,.0f}/s", "cyan"),
            ("  ", ""), (hms(s.elapsed()), "dim"),
            no_wrap=True, overflow="ellipsis",
        )
        line2 = Text("Fails ", style="dim", no_wrap=True, overflow="ellipsis")
        for key, label, color in FAILS:
            line2.append(f"{label.split()[0]} ", style="dim")
            line2.append(f"{s.fails.get(key, 0):,}  ", style=color)
        return Panel(Group(line1, line2), box=box.ROUNDED, border_style="blue", padding=(0, 1))

    def _best(self, rows, compact):
        s = self.state
        hits = s.top(rows)
        title = f"Best IPs · {s.found:,} found"
        if not hits:
            body = Text("\nSearching for working IPs…", style="dim italic", justify="center")
        else:
            show_verify = s.phase == "Verify" or any(h.loss is not None for h in hits)
            body = results_table(hits, show_verify, compact)
        return Panel(body, title=title, title_align="left", border_style="green", box=box.ROUNDED)

    def _log(self, lines):
        text = Text(no_wrap=True, overflow="ellipsis")
        for i, (ts, msg) in enumerate(list(self.state.logs)[-lines:]):
            if i:
                text.append("\n")
            text.append(f"{ts}  ", style="dim")
            text.append(msg)
        return Panel(text, title="Log", title_align="left", border_style="grey50", box=box.ROUNDED)

    def _footer(self):
        if self.state.stopping:
            return Text(" Stopping… press Ctrl+C again to quit immediately", style="bold yellow")
        return Text.assemble((" Ctrl+C ", "reverse"), ("  stop & save    ", "dim"),
                             ("live results → working_ips.txt", "dim"))


def diagnose(state):
    s = state
    if s.tested == 0:
        return []
    if s.found == 0:
        if s.filtered:
            return ["Working IPs were found, but none in the colos you selected."]
        worst = max(s.fails, key=s.fails.get)
        return [HINTS[worst]] if s.fails[worst] else []
    if s.fails.get("cert"):
        return [f"{s.fails['cert']:,} IPs presented a certificate that doesn't match your SNI and were skipped."]
    return []


def render_summary(state, saved, sink, compact=False):
    s = state
    done = s.phase == "Done"
    parts = [Text.assemble(
        ("✓ Scan complete" if done else "■ Scan stopped", "bold green" if done else "bold yellow"),
        (f"   {s.tested:,} tested · {s.found:,} found · {hms(s.elapsed())}", "dim"),
    )]

    best = [h for h in s.ranked() if not (h.loss is not None and h.loss >= 1)][:10]
    if best:
        verified = any(h.loss is not None for h in best)
        parts += [Text(""), results_table(best, verified, compact)]

    hints = diagnose(s)
    if hints:
        parts.append(Text(""))
        parts += [Text("• " + h, style="yellow") for h in hints]

    parts.append(Text(""))
    if saved:
        parts.append(Text.assemble(
            ("Saved ", "dim"), (f"{saved} IPs", "bold green"),
            (f" → {sink.ips_path}   details → {sink.csv_path}", "dim"),
        ))
    else:
        parts.append(Text("No working IPs found.", style="dim"))

    return Panel(Group(*parts), title=f"CF-Scanner Pro v{__version__}", title_align="left",
                 border_style="green" if done else "yellow", box=box.ROUNDED, padding=(1, 2))
