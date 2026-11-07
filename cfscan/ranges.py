"""Cloudflare IPv4 ranges: built-in list, file loading, online update, /24 blocks."""
import ipaddress
import os
import urllib.request

CF_URL = "https://www.cloudflare.com/ips-v4"

# Official list from cloudflare.com/ips - used when the ranges file is missing or empty.
BUILTIN_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]


def parse_ranges(lines):
    """Parses CIDR / single-IP lines ('#' starts a comment). IPv4 only, overlaps merged."""
    nets = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    return list(ipaddress.collapse_addresses(nets))


def load_ranges(path):
    """Returns (networks, source_label)."""
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            nets = parse_ranges(f)
        if nets:
            return nets, path
    return parse_ranges(BUILTIN_RANGES), "built-in list"


def update_ranges(path, timeout=15):
    """Downloads the current list from Cloudflare and writes it to `path`. Returns the count."""
    req = urllib.request.Request(CF_URL, headers={"User-Agent": "CF-Scanner-Pro"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "ignore")
    nets = parse_ranges(text.splitlines())
    if not nets:
        raise ValueError("Cloudflare returned an empty list")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Cloudflare IPv4 ranges - {CF_URL}\n")
        f.write("# One CIDR per line. '#' starts a comment. Refresh: cfscan ranges update\n")
        f.writelines(f"{n}\n" for n in nets)
    return len(nets)


def to_blocks(nets):
    """Splits networks into /24 blocks -> list of (base_int, size)."""
    blocks = []
    for net in nets:
        base, size = int(net.network_address), net.num_addresses
        if net.prefixlen >= 24:
            blocks.append((base, size))
        else:
            blocks.extend((b, 256) for b in range(base, base + size, 256))
    return blocks


def host_offsets(size):
    """Usable host offsets inside a block (skips .0 and .255 of a full /24)."""
    return range(1, size - 1) if size > 2 else range(size)


def count_hosts(blocks):
    return sum(len(host_offsets(size)) for _, size in blocks)


def int_to_ip(n):
    return f"{n >> 24}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def expand_targets(items, limit=65536):
    """Turns IPs / CIDRs into a de-duplicated IP list (order kept). Raises ValueError on junk."""
    seen, out = set(), []
    for raw in items:
        raw = raw.split("#", 1)[0].strip()
        if not raw:
            continue
        net = ipaddress.ip_network(raw, strict=False)  # ValueError if invalid
        if net.version != 4:
            raise ValueError(f"{raw}: only IPv4 is supported")
        hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
        for h in hosts:
            ip = str(h)
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
                if len(out) > limit:
                    raise ValueError(f"too many IPs (limit {limit:,})")
    return out
