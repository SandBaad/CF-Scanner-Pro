#!/usr/bin/env python3
"""CF-Scanner Pro - find working Cloudflare edge IPs for your SNI."""
import asyncio
import sys

if sys.version_info < (3, 8):
    sys.exit("CF-Scanner Pro requires Python 3.8 or newer.")

from rich.console import Console
from rich.live import Live

from modules import ranges
from modules.config import get_config
from modules.engine import Prober
from modules.output import ResultSink
from modules.scanner import Scanner, ScanState
from modules.ui import Dashboard, render_summary


def fit_concurrency(wanted):
    """Raises the open-file limit where possible (Linux / macOS / Termux)."""
    try:
        import resource
    except ImportError:  # Windows: no per-process socket limit to worry about
        return wanted
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return wanted
    need = wanted + 64
    if soft < need:
        new = need if hard == resource.RLIM_INFINITY else min(need, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
            soft = new
        except (ValueError, OSError):
            pass
    return max(1, min(wanted, soft - 64))


def main():
    console = Console()
    cfg = get_config(console)

    nets, source = ranges.load_ranges(cfg["subnets_file"])
    blocks = ranges.to_blocks(nets)
    if not blocks:
        console.print("[bold red]No valid IPv4 ranges found.[/]")
        sys.exit(1)

    concurrency = fit_concurrency(cfg["concurrency"])
    if concurrency < cfg["concurrency"]:
        console.print(f"[yellow]Open-file limit is low - using {concurrency} connections.[/]")
    cfg = dict(cfg, concurrency=concurrency)

    state = ScanState(cfg["colos"])
    state.log(f"Loaded {len(nets)} ranges ({len(blocks):,} /24 blocks) from {source}")
    sink = ResultSink()
    state.sink = sink
    prober = Prober(cfg["sni"], cfg["port"], cfg["timeout"], cfg["verify_cert"], cfg["http_check"])
    scanner = Scanner(cfg, blocks, prober, state)

    try:
        with Live(Dashboard(state, cfg), console=console, screen=True, auto_refresh=False) as live:
            asyncio.run(scanner.run(live))
    except (KeyboardInterrupt, asyncio.CancelledError):
        state.stopping = True
    finally:
        state.finish()
        saved = sink.finalize(state.ranked())

    console.print(render_summary(state, saved, sink, compact=console.width < 96))


if __name__ == "__main__":
    main()
