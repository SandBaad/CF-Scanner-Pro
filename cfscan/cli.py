"""Command line: cfscan scan | test | ranges | show."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys

from cfscan import APP_NAME, __version__, config, ranges
from cfscan.engine import Prober, SpeedTester
from cfscan.output import ResultSink, build_report, hit_dict, load_report
from cfscan.scanner import ScanState, Scanner, rank_key
from cfscan.term import Keys, Screen, Theme, can_unicode, enable_windows_ansi, wants_color
from cfscan.tui import Dashboard, Line, LiveUI, PlainUI, box, render_summary

EXAMPLES = """\
examples:
  cfscan scan sub.example.com              smart scan (recommended)
  cfscan scan sub.example.com -m quick     fast overview
  cfscan scan sub.example.com --colo FRA,AMS -n 50
  cfscan scan --save sub.example.com       remember settings, then just: cfscan scan
  cfscan test 104.16.1.10 172.67.0.0/28    re-check specific IPs / small CIDRs
  cfscan test -f working_ips.txt           re-check your last results
  cfscan ranges update                     refresh Cloudflare ranges
  cfscan show                              print the last results again
"""


# ---------------------------------------------------------------- helpers

def theme_for(stream, args):
    return Theme(color=wants_color(stream, getattr(args, "no_color", False)), unicode=can_unicode(stream))


def die(msg, code=2):
    th = Theme(color=wants_color(sys.stderr), unicode=can_unicode(sys.stderr))
    sys.stderr.write(th.paint("error: ", "bad") + msg + "\n")
    sys.exit(code)


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


def resolve(args, saved, list_mode=False):
    """Defaults <- mode preset <- saved settings <- command-line flags."""
    cfg = dict(config.DEFAULTS)
    cfg.update(saved)
    mode = getattr(args, "mode", None) or cfg.get("mode", "smart")
    cfg.update(config.MODES[mode], mode=mode)

    flags = {
        "sni": args.sni or getattr(args, "sni_opt", None),
        "port": args.port, "timeout": args.timeout, "concurrency": args.concurrency,
        "speed_url": args.speed_url, "speed_size": args.speed_size, "speed_timeout": args.speed_timeout,
        "speed_top": args.speed_top, "verify_rounds": args.rounds,
        "out": args.out,
    }
    for name in ("target", "verify_top", "ranges", "seed"):
        flags[name] = getattr(args, name, None)
    cfg.update({k: v for k, v in flags.items() if v is not None})
    if getattr(args, "colo", None) is not None:
        cfg["colos"] = config.parse_colos(args.colo)
    if args.insecure:
        cfg["insecure"] = True
    if args.no_http:
        cfg["no_http"] = True
    if args.no_speed:
        cfg["speed"] = False
    if cfg["colos"] and cfg["no_http"]:
        cfg["no_http"] = False  # colo comes from the trace
    if list_mode:
        cfg["mode"] = "check"

    # ---- validation ----
    if not cfg["sni"]:
        cfg["sni"] = ask_sni()
    cfg["sni"] = cfg["sni"].strip().lower()
    if not config.valid_domain(cfg["sni"]):
        die(f"'{cfg['sni']}' is not a valid domain (example: sub.example.com)")
    if not 1 <= cfg["port"] <= 65535:
        die("--port must be 1-65535")
    if not 0.3 <= cfg["timeout"] <= 30:
        die("--timeout must be between 0.3 and 30 seconds")
    if not 1 <= cfg["concurrency"] <= 4000:
        die("--concurrency must be between 1 and 4000")
    if cfg["verify_rounds"] < 1:
        die("--rounds must be at least 1")
    return cfg


def ask_sni():
    if not sys.stdin.isatty():
        die("give your domain: cfscan scan sub.example.com")
    th = Theme(color=wants_color(sys.stdout), unicode=can_unicode(sys.stdout))
    try:
        return input(th.paint("? ", "accent") + th.paint("Your domain (SNI) behind Cloudflare: ", "bold")).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(130)


# ---------------------------------------------------------------- running

def execute(args, cfg, blocks=(), targets=None, source=""):
    out_stream = sys.stdout
    want_json = getattr(args, "json", False)
    tui = out_stream.isatty() and sys.stdin.isatty() and not args.plain and not want_json
    th = theme_for(out_stream, args)

    wanted = cfg["concurrency"]
    cfg["concurrency"] = fit_concurrency(wanted)

    state = ScanState(cfg["colos"])
    save = targets is None or args.save_results
    sink = ResultSink(cfg["out"], live=targets is None) if save else None
    state.sink = sink
    if cfg["concurrency"] < wanted:
        state.log(f"Open-file limit is low - using {cfg['concurrency']} connections", "warn")
    if targets is None:
        state.log(f"Loaded {len(blocks):,} /24 blocks from {source}")
    else:
        state.log(f"Checking {len(targets):,} IPs x {cfg['verify_rounds']} rounds")

    prober = Prober(cfg["sni"], cfg["port"], cfg["timeout"], not cfg["insecure"], not cfg["no_http"])
    speed = None
    if cfg["speed"] and cfg["speed_top"] > 0:
        try:
            speed = SpeedTester(cfg["speed_url"] or None, cfg["speed_size"], cfg["speed_timeout"], not cfg["insecure"])
        except ValueError as e:
            die(str(e))
    scanner = Scanner(cfg, prober, state, blocks=blocks, targets=targets, speed=speed)

    try:
        if tui:
            dash = Dashboard(state, cfg, th, sink.ips_path if sink and sink.live else "")
            with Screen(out_stream) as screen, Keys() as keys:
                try:
                    asyncio.run(scanner.run(LiveUI(dash, screen, keys)))
                except KeyboardInterrupt:
                    state.stopping = True
        else:
            ui = PlainUI(state, theme_for(sys.stderr, args), sys.stderr, quiet=want_json)
            try:
                asyncio.run(scanner.run(ui))
            except KeyboardInterrupt:
                state.stopping = True
    finally:
        state.finish()

    ranked = state.ranked()
    meta = {"sni": cfg["sni"], "mode": cfg["mode"], "port": cfg["port"],
            "duration_s": round(state.elapsed(), 1), "tested": state.tested, "found": state.found,
            "speed_host": speed.host if speed else None}
    saved = sink.finalize(ranked, meta) if sink else 0

    if want_json:
        print(json.dumps(build_report(meta, [hit_dict(i, h) for i, h in enumerate(ranked, 1)]), indent=2))
    else:
        width = shutil.get_terminal_size((100, 30)).columns - 1
        for line in render_summary(th, state, ranked, width, saved, sink, speed.host if speed else ""):
            print(line)
    return 0 if any(h.alive for h in ranked) else 1


# ---------------------------------------------------------------- commands

def cmd_scan(args):
    saved = config.load_saved()
    cfg = resolve(args, saved)
    if args.save:
        path = config.save(cfg)
        print(theme_for(sys.stdout, args).paint(f"Settings saved to {path}", "dim"))
    nets, source = ranges.load_ranges(cfg["ranges"])
    blocks = ranges.to_blocks(nets)
    if not blocks:
        die("no valid IPv4 ranges found")
    return execute(args, cfg, blocks=blocks, source=source)


def cmd_test(args):
    items = list(args.ips)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                items += [ln.split(",")[0] for ln in f]
        except OSError as e:
            die(f"can't read {args.file}: {e.strerror}")
    if not items and not sys.stdin.isatty():
        items = sys.stdin.read().split()
    try:
        targets = ranges.expand_targets(items, limit=16384)
    except ValueError as e:
        die(f"bad IP/CIDR: {e}")
    if not targets:
        die("nothing to test - give IPs, CIDRs, or -f FILE")
    args.save_results = bool(args.out)
    cfg = resolve(args, config.load_saved(), list_mode=True)
    cfg["speed_top"] = args.speed_top if args.speed_top is not None else min(len(targets), 20)
    return execute(args, cfg, targets=targets)


def cmd_ranges(args):
    th = theme_for(sys.stdout, args)
    path = args.file or config.load_saved().get("ranges") or config.DEFAULTS["ranges"]
    if args.action == "update":
        print(th.paint("Downloading Cloudflare IP ranges" + th.ell, "dim"))
        try:
            n = ranges.update_ranges(path)
        except Exception as e:
            die(f"update failed: {e} (the current file / built-in list still works)", 1)
        print(th.paint(f"{th.done} ", "good") + f"Saved {n} ranges to {path}")
        return 0
    nets, source = ranges.load_ranges(path)
    blocks = ranges.to_blocks(nets)
    width = min(shutil.get_terminal_size((80, 24)).columns - 1, 70)
    lines = [Line((f"{str(n):<20}", "ip"), (f"{n.num_addresses:>12,} IPs", "dim")) for n in nets]
    lines += [Line(), Line(("Total ", "dim"), (f"{len(nets)} ranges {th.dot} {len(blocks):,} /24 blocks "
                                               f"{th.dot} {ranges.count_hosts(blocks):,} IPs", "bold"))]
    for line in box(th, f"Ranges {th.dot} {source}", lines, width):
        print(line)
    return 0


def cmd_show(args):
    th = theme_for(sys.stdout, args)
    path = args.path or os.path.join(config.load_saved().get("out", "."), "results.json")
    if os.path.isdir(path):
        path = os.path.join(path, "results.json")
    try:
        data, hits = load_report(path)
    except (OSError, ValueError, KeyError) as e:
        die(f"can't read {path}: {e}")
    hits.sort(key=rank_key)
    state = ScanState()
    state.tested, state.found = data.get("tested", 0), data.get("found", 0)
    state.finish()
    state._end = state._start + (data.get("duration_s") or 0)  # show the original duration
    if args.limit:
        hits = hits[: args.limit]
    if args.ips:
        for h in hits:
            if h.alive:
                print(h.ip)
        return 0
    note = f"{data.get('sni', '?')} {th.dot} {data.get('mode', '?')} {th.dot} {data.get('date', '')}"
    width = shutil.get_terminal_size((100, 30)).columns - 1
    for line in render_summary(th, state, hits, width, title_note=note):
        print(line)
    return 0


def cmd_home(args):
    th = theme_for(sys.stdout, args)
    saved = config.load_saved()
    width = min(shutil.get_terminal_size((90, 24)).columns - 1, 92)
    cmds = [
        ("scan [SNI]", "scan Cloudflare ranges for clean, fast IPs"),
        ("test IP|CIDR...", "re-check specific IPs (or -f working_ips.txt)"),
        ("ranges [update]", "show or refresh the Cloudflare ranges"),
        ("show", "print the last results again"),
    ]
    lines = [Line(("Find clean, fast Cloudflare edge IPs for your own domain (SNI).", "text")), Line()]
    lines.append(Line(("Commands", "head")))
    for c, d in cmds:
        lines.append(Line(("  cfscan ", "dim"), (f"{c:<17}", "accent"), (d, "text")))
    lines += [Line(), Line(("Modes", "head"))]
    for m, d in config.MODE_HELP.items():
        lines.append(Line((f"  {m:<7}", "accent2"), (d, "dim")))
    lines += [Line(), Line(("Quick start", "head"))]
    if saved.get("sni"):
        lines.append(Line(("  cfscan scan", "goodb"), (f"     uses your saved domain {saved['sni']}", "dim")))
    else:
        lines.append(Line(("  cfscan scan sub.example.com", "goodb")))
    lines.append(Line(("  cfscan scan -h", "accent"), ("    all options", "dim")))
    for line in box(th, f"{APP_NAME} v{__version__}", lines, width):
        print(line)
    return 0


# ---------------------------------------------------------------- parser

def add_probe_opts(p):
    g = p.add_argument_group("connection")
    g.add_argument("-p", "--port", type=int, help="TLS port: 443 2053 2083 2087 2096 8443 (default 443)")
    g.add_argument("-t", "--timeout", type=float, help="seconds per check (default 2.5)")
    g.add_argument("-c", "--concurrency", type=int, help="parallel connections (default 200)")
    g.add_argument("-k", "--insecure", "--no-verify", dest="insecure", action="store_true",
                   help="don't verify the certificate against the SNI")
    g.add_argument("--no-http", action="store_true", help="skip the /cdn-cgi/trace check (no colo info)")
    g.add_argument("--colo", help="only keep these data centers, e.g. FRA,AMS,IST")
    s = p.add_argument_group("quality")
    s.add_argument("--rounds", type=int, help="re-test rounds per IP for median/jitter/loss")
    s.add_argument("--speed-top", type=int, help="download-test the best N IPs")
    s.add_argument("--no-speed", action="store_true", help="skip the download test")
    s.add_argument("--speed-url", help="download through your own file, e.g. https://sub.example.com/10mb.bin")
    s.add_argument("--speed-size", type=float, help="MB to download from speed.cloudflare.com (default 2)")
    s.add_argument("--speed-timeout", type=float, help="seconds per download test (default 8)")
    o = p.add_argument_group("output")
    o.add_argument("-o", "--out", help="folder for working_ips.txt / results.csv / results.json")
    o.add_argument("--plain", action="store_true", help="simple log lines instead of the dashboard")
    o.add_argument("--json", action="store_true", help="print results as JSON on stdout")
    o.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable colors")


def build_parser():
    fmt = lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=34)  # noqa: E731
    p = argparse.ArgumentParser(prog="cfscan", description=f"{APP_NAME} - clean Cloudflare IPs for your SNI.",
                                epilog=EXAMPLES, formatter_class=fmt)
    p.add_argument("-V", "--version", action="version", version=f"{APP_NAME} {__version__}")
    p.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable colors")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    s = sub.add_parser("scan", help="scan Cloudflare ranges", formatter_class=fmt,
                       description="Scan Cloudflare ranges and rank the IPs that really work for your SNI.",
                       epilog=EXAMPLES)
    s.add_argument("sni", nargs="?", help="your domain behind Cloudflare (saved one if omitted)")
    s.add_argument("--sni", dest="sni_opt", help=argparse.SUPPRESS)
    s.add_argument("-m", "--mode", choices=list(config.MODES), help="quick | smart | deep | full (default smart)")
    s.add_argument("-n", "--target", type=int, help="stop discovery after N working IPs (0 = no limit)")
    s.add_argument("--verify-top", type=int, help="re-test the best N IPs")
    s.add_argument("-r", "--ranges", "--subnets", dest="ranges", help="ranges file (default subnets.txt)")
    s.add_argument("--save", action="store_true", help="save these settings as defaults")
    s.add_argument("--seed", type=int, help=argparse.SUPPRESS)
    s.add_argument("-y", "--yes", action="store_true", help=argparse.SUPPRESS)  # v2 compatibility
    add_probe_opts(s)
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser("test", aliases=["check"], help="re-check specific IPs", formatter_class=fmt,
                       description="Test given IPs / CIDRs (max 16k) with several rounds and a download test.")
    t.add_argument("ips", nargs="*", metavar="IP", help="IPs or CIDRs, e.g. 104.16.1.10 172.67.0.0/28")
    t.add_argument("-f", "--file", help="read IPs from a file (e.g. working_ips.txt or results.csv)")
    t.add_argument("--sni", help="domain (saved one if omitted)")
    add_probe_opts(t)
    t.set_defaults(func=cmd_test, sni_opt=None)

    r = sub.add_parser("ranges", help="show / update Cloudflare ranges", formatter_class=fmt)
    r.add_argument("action", nargs="?", choices=["list", "update"], default="list")
    r.add_argument("-f", "--file", help="ranges file (default subnets.txt)")
    r.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    r.set_defaults(func=cmd_ranges)

    sh = sub.add_parser("show", help="print the last results", formatter_class=fmt)
    sh.add_argument("path", nargs="?", help="results.json or its folder")
    sh.add_argument("-l", "--limit", type=int, help="only the best N")
    sh.add_argument("--ips", action="store_true", help="only print IPs, one per line")
    sh.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    sh.set_defaults(func=cmd_show)
    return p


def legacy_argv(argv):
    """v2 used flags only (`main.py --sni x`). Keep those working."""
    if not argv or not argv[0].startswith("-") or argv[0] in ("-h", "--help", "-V", "--version", "--no-color"):
        return argv
    if "--update-ranges" in argv:
        return ["ranges", "update"]
    return ["scan"] + argv


def main(argv=None):
    enable_windows_ansi()
    argv = legacy_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        sys.exit(cmd_home(args))
    try:
        sys.exit(args.func(args))
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)

