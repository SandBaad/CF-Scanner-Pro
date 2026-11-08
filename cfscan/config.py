"""Presets, defaults and saved settings."""
import json
import os
import re

MODES = {
    #          sample/24  top /24s to dig  IPs each  re-test  rounds  speed-test
    "quick": dict(sample=1, expand_blocks=0, expand=0, verify_top=20, verify_rounds=3, speed_top=5),
    "smart": dict(sample=2, expand_blocks=25, expand=24, verify_top=40, verify_rounds=5, speed_top=10),
    "deep": dict(sample=4, expand_blocks=80, expand=60, verify_top=80, verify_rounds=6, speed_top=15),
    "full": dict(sample=0, expand_blocks=0, expand=0, verify_top=50, verify_rounds=5, speed_top=10),
}
MODE_HELP = {
    "quick": "1 IP per /24, fastest overview (~1 min)",
    "smart": "2 per /24, then dig into the 25 fastest /24s (recommended)",
    "deep": "4 per /24, dig into the 80 fastest /24s, more re-tests",
    "full": "every IP in the ranges (~1.5M, slow)",
}

DEFAULTS = dict(
    sni="",
    port=443,
    mode="smart",
    timeout=2.5,
    concurrency=200,
    target=0,
    colos=[],
    insecure=False,
    no_http=False,
    speed=True,
    speed_url="",
    speed_size=2.0,
    speed_timeout=8.0,
    speed_par=1,
    ranges="subnets.txt",
    out=".",
    seed=None,
    **MODES["smart"],
)

# Only these survive `--save`; mode presets are always re-derived from `mode`.
SAVED_KEYS = ("sni", "port", "mode", "timeout", "concurrency", "colos", "insecure",
              "no_http", "speed", "speed_url", "speed_size", "ranges", "out")

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)
HTTPS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)


def config_path():
    if os.environ.get("CFSCAN_CONFIG"):
        return os.environ["CFSCAN_CONFIG"]
    if os.name == "nt" and os.environ.get("APPDATA"):
        base = os.environ["APPDATA"]
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "cfscan", "config.json")


def _legacy(data):
    """Maps a v1/v2 config.json onto v3 keys."""
    if "domain" in data and "sni" not in data:
        data["sni"] = data.pop("domain")
    if data.get("verify_cert") is False:
        data["insecure"] = True
    if data.get("http_check") is False:
        data["no_http"] = True
    if "subnets_file" in data:
        data["ranges"] = data.pop("subnets_file")
    return data


def load_saved():
    for path in (config_path(), "config.json"):  # second: v2 file next to main.py
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data = _legacy(data)
            out = {k: data[k] for k in SAVED_KEYS if k in data}
            if out.get("mode") not in MODES:
                out.pop("mode", None)
            return out
    return {}


def save(cfg):
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({k: cfg[k] for k in SAVED_KEYS}, f, indent=2)
    return path


def parse_colos(text):
    return [c.strip().upper() for c in (text or "").split(",") if c.strip()]


def valid_domain(text):
    return bool(DOMAIN_RE.match((text or "").strip()))
