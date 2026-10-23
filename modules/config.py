"""Settings: interactive menu & wizard, CLI arguments, config.json."""
import argparse
import json
import os
import re
import sys

import questionary
from questionary import Choice, Style
from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules import __version__, ranges

CONFIG_FILE = "config.json"

MODES = {
    "smart": {"sample": 2, "expand": 30, "target": 100, "verify_top": 30, "concurrency": 200},
    "quick": {"sample": 1, "expand": 0, "target": 0, "verify_top": 20, "concurrency": 200},
    "full": {"sample": 0, "expand": 0, "target": 0, "verify_top": 30, "concurrency": 300},
}
MODE_TITLES = {
    "smart": "Smart  - sample every /24, then dig into live ones (recommended)",
    "quick": "Quick  - one IP per /24, fastest overview",
    "full": "Full   - every single IP in the ranges (slow)",
}
DEFAULTS = {
    "sni": "",
    "port": 443,
    "mode": "smart",
    "timeout": 2.0,
    "verify_rounds": 3,
    "verify_cert": True,
    "http_check": True,
    "colos": [],
    "subnets_file": "subnets.txt",
    **MODES["smart"],
}

STYLE = Style([
    ("qmark", "fg:#00afff bold"),
    ("question", "bold"),
    ("answer", "fg:#5fd75f bold"),
    ("pointer", "fg:#00afff bold"),
    ("highlighted", "fg:#00afff bold"),
    ("selected", "fg:#5fd75f"),
    ("instruction", "fg:#808080 italic"),
])

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)


# ---------- helpers ----------

def _ask(question):
    """questionary returns None on Ctrl+C - exit cleanly instead of crashing."""
    answer = question.ask()
    if answer is None:
        sys.exit(0)
    return answer


def _domain(text):
    return bool(DOMAIN_RE.match(text.strip())) or "Enter a valid domain, e.g. sub.example.com"


def _num(cast, lo, hi=None):
    def check(text):
        try:
            value = cast(text)
        except ValueError:
            return "Enter a number"
        if value < lo or (hi is not None and value > hi):
            return f"Enter a value between {lo} and {hi}" if hi is not None else f"Enter a value ≥ {lo}"
        return True
    return check


def _colos(text):
    return [c.strip().upper() for c in text.split(",") if c.strip()]


def load_saved():
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if "domain" in data and "sni" not in data:  # config.json from v1
        data["sni"] = data.pop("domain")
    return {k: v for k, v in data.items() if k in DEFAULTS}


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def banner(console):
    console.print(Panel(
        Group(Text.assemble(("⚡ CF-Scanner Pro", "bold cyan"), (f"  v{__version__}", "dim")),
              Text("Find clean Cloudflare edge IPs for your SNI", style="dim")),
        box=box.ROUNDED, border_style="cyan", expand=False, padding=(0, 2),
    ))


def summary_panel(cfg, title):
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bold")
    t.add_row("SNI", cfg["sni"])
    t.add_row("Mode", cfg["mode"].title())
    t.add_row("Connections", str(cfg["concurrency"]))
    t.add_row("Timeout", f"{cfg['timeout']}s")
    if cfg["sample"]:
        t.add_row("Sample per /24", str(cfg["sample"]))
    if cfg["expand"]:
        t.add_row("Expand live /24s", f"+{cfg['expand']} IPs each")
    t.add_row("Stop after", f"{cfg['target']} IPs" if cfg["target"] else "no limit")
    t.add_row("Re-test best", f"{cfg['verify_top']} × {cfg['verify_rounds']}" if cfg["verify_top"] else "off")
    checks = "TLS" + (" + certificate" if cfg["verify_cert"] else "") + (" + HTTP trace" if cfg["http_check"] else "")
    t.add_row("Checks", checks)
    t.add_row("Colo filter", ", ".join(cfg["colos"]) or "any")
    return Panel(t, title=title, title_align="left", border_style="cyan", box=box.ROUNDED, expand=False)


def update_ranges_ui(console, path):
    with console.status("Downloading Cloudflare IP ranges…"):
        try:
            n = ranges.update_ranges(path)
        except Exception as e:  # network errors, HTTP errors, empty list…
            console.print(f"[red]✗ Update failed: {e}[/]")
            console.print("[dim]The existing file or built-in list will be used.[/]")
            return
    console.print(f"[green]✓ Saved {n} ranges to {path}[/]")


# ---------- wizard ----------

def wizard(console, saved):
    sni = _ask(questionary.text("Domain (SNI) on Cloudflare:", default=saved.get("sni", ""),
                                validate=_domain, style=STYLE)).strip().lower()
    mode = _ask(questionary.select(
        "Scan mode:",
        choices=[Choice(MODE_TITLES[m], value=m) for m in MODES],
        default=saved.get("mode", "smart") if saved.get("mode") in MODES else "smart",
        style=STYLE,
    ))

    keep = ("port", "timeout", "verify_rounds", "verify_cert", "http_check", "colos", "subnets_file")
    cfg = {**DEFAULTS, **{k: saved[k] for k in keep if k in saved}, **MODES[mode], "sni": sni, "mode": mode}

    if _ask(questionary.confirm("Customize advanced settings?", default=False, style=STYLE)):
        cfg["concurrency"] = int(_ask(questionary.text(
            "Parallel connections:", default=str(cfg["concurrency"]), validate=_num(int, 1, 2000), style=STYLE)))
        cfg["timeout"] = float(_ask(questionary.text(
            "Timeout per IP (seconds):", default=str(cfg["timeout"]), validate=_num(float, 0.3, 30), style=STYLE)))
        if mode != "full":
            cfg["sample"] = int(_ask(questionary.text(
                "IPs to sample from each /24:", default=str(cfg["sample"]), validate=_num(int, 1, 254), style=STYLE)))
        if mode == "smart":
            cfg["expand"] = int(_ask(questionary.text(
                "Extra IPs to test in each live /24:", default=str(cfg["expand"]),
                validate=_num(int, 0, 254), style=STYLE)))
        cfg["target"] = int(_ask(questionary.text(
            "Stop after finding N IPs (0 = no limit):", default=str(cfg["target"]),
            validate=_num(int, 0), style=STYLE)))
        cfg["verify_top"] = int(_ask(questionary.text(
            "Re-test the best N IPs (0 = off):", default=str(cfg["verify_top"]),
            validate=_num(int, 0, 500), style=STYLE)))
        cfg["colos"] = _colos(_ask(questionary.text(
            "Only keep these colos, e.g. FRA,AMS (empty = any):", default=",".join(cfg["colos"]), style=STYLE)))
        cfg["verify_cert"] = _ask(questionary.confirm(
            "Verify the TLS certificate against the SNI?", default=cfg["verify_cert"], style=STYLE))
        cfg["http_check"] = _ask(questionary.confirm(
            "Send a test request (/cdn-cgi/trace) after the handshake?", default=cfg["http_check"], style=STYLE))
        if cfg["colos"] and not cfg["http_check"]:
            console.print("[yellow]The colo filter needs the HTTP check - enabling it.[/]")
            cfg["http_check"] = True
    return cfg


# ---------- CLI ----------

def parse_args():
    p = argparse.ArgumentParser(prog="main.py", description="Find working Cloudflare edge IPs for your SNI.")
    p.add_argument("--sni", help="domain on Cloudflare (skips the menu)")
    p.add_argument("--mode", choices=list(MODES), help="scan preset")
    p.add_argument("-c", "--concurrency", type=int, help="parallel connections")
    p.add_argument("-t", "--timeout", type=float, help="seconds per IP")
    p.add_argument("--target", type=int, help="stop after N working IPs (0 = no limit)")
    p.add_argument("--colo", help="comma-separated colo filter, e.g. FRA,AMS")
    p.add_argument("--subnets", help="ranges file (default: subnets.txt)")
    p.add_argument("--no-verify", action="store_true", help="don't verify the certificate")
    p.add_argument("--no-http", action="store_true", help="skip the /cdn-cgi/trace check")
    p.add_argument("-y", "--yes", action="store_true", help="start with saved settings, no prompts")
    p.add_argument("--update-ranges", action="store_true", help="download the latest Cloudflare ranges and exit")
    return p.parse_args()


def config_from_args(args, saved):
    cfg = {**DEFAULTS, **saved}
    if args.mode:
        cfg.update(MODES[args.mode], mode=args.mode)
    overrides = {"sni": args.sni, "concurrency": args.concurrency, "timeout": args.timeout,
                 "target": args.target, "subnets_file": args.subnets}
    cfg.update({k: v for k, v in overrides.items() if v is not None})
    if args.colo is not None:
        cfg["colos"] = _colos(args.colo)
    if args.no_verify:
        cfg["verify_cert"] = False
    if args.no_http:
        cfg["http_check"] = False
    if cfg["colos"]:
        cfg["http_check"] = True
    if not DOMAIN_RE.match(cfg["sni"] or ""):
        sys.exit("A valid --sni is required (or run without arguments to use the menu).")
    cfg["sni"] = cfg["sni"].lower()
    return cfg


# ---------- entry ----------

def get_config(console):
    args = parse_args()
    saved = load_saved()
    ranges_file = args.subnets or saved.get("subnets_file") or DEFAULTS["subnets_file"]

    if args.update_ranges:
        update_ranges_ui(console, ranges_file)
        sys.exit(0)

    if args.sni or args.yes:
        return config_from_args(args, saved)

    banner(console)
    while True:
        has_saved = bool(DOMAIN_RE.match(saved.get("sni", "") or ""))
        choices = []
        if has_saved:
            console.print(summary_panel({**DEFAULTS, **saved}, "Last settings"))
            choices.append(Choice("Start scan with last settings", value="start"))
        choices += [
            Choice("New scan setup", value="setup"),
            Choice("Update Cloudflare IP ranges", value="update"),
            Choice("Exit", value="exit"),
        ]
        action = _ask(questionary.select("What would you like to do?", choices=choices, style=STYLE))

        if action == "exit":
            sys.exit(0)
        if action == "update":
            update_ranges_ui(console, ranges_file)
            continue
        if action == "start":
            cfg = {**DEFAULTS, **saved}
        else:
            cfg = wizard(console, saved)
            console.print(summary_panel(cfg, "New settings"))
            if _ask(questionary.confirm("Save these settings for next time?", default=True, style=STYLE)):
                save_config(cfg)
                saved = cfg
            if not _ask(questionary.confirm("Start the scan now?", default=True, style=STYLE)):
                continue

        if args.subnets:
            cfg["subnets_file"] = args.subnets
        return cfg
