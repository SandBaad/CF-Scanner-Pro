"""Result files: live append while scanning, ranked rewrite at the end, JSON for `show`."""
import csv
import json
import os
import time

from cfscan import __version__
from cfscan.colos import city
from cfscan.engine import Hit

IPS_FILE = "working_ips.txt"
CSV_FILE = "results.csv"
JSON_FILE = "results.json"


def hit_dict(rank, h):
    return {
        "rank": rank,
        "ip": h.ip,
        "ping_ms": h.ping if h.ping is not None else h.tcp,
        "tls_ms": h.latency,
        "jitter_ms": h.jitter,
        "loss_pct": None if h.loss is None else round(h.loss * 100),
        "speed_mbps": h.speed,
        "speed_error": h.speed_err or None,
        "colo": h.colo,
        "city": city(h.colo),
        "verified": h.verified,
        "first_seen": h.seen,
    }


def hit_from_dict(d):
    h = Hit(d["ip"], d.get("ping_ms") or 0, d.get("tls_ms") or 0, d.get("colo") or "-", d.get("first_seen") or "")
    if d.get("verified"):
        h.ping, h.hs, h.jitter = d.get("ping_ms"), d.get("tls_ms"), d.get("jitter_ms")
        h.loss = (d.get("loss_pct") or 0) / 100
    h.speed = d.get("speed_mbps")
    h.speed_err = d.get("speed_error") or ""
    return h


class ResultSink:
    def __init__(self, outdir=".", live=True):
        self.outdir = outdir
        self.live = live
        self.ips_path = os.path.join(outdir, IPS_FILE)
        self.csv_path = os.path.join(outdir, CSV_FILE)
        self.json_path = os.path.join(outdir, JSON_FILE)
        self._fh = None

    def add(self, hit):
        if not self.live:
            return
        # Opened lazily: a scan that finds nothing never wipes previous results.
        if self._fh is None:
            os.makedirs(self.outdir, exist_ok=True)
            self._fh = open(self.ips_path, "w", encoding="utf-8")
        self._fh.write(hit.ip + "\n")
        self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def finalize(self, ranked, meta):
        """Rewrites all files ranked best-first. Returns the number of working IPs saved."""
        self.close()
        if not ranked:
            return 0
        os.makedirs(self.outdir, exist_ok=True)
        alive = [h for h in ranked if h.alive]
        with open(self.ips_path, "w", encoding="utf-8") as f:
            f.writelines(h.ip + "\n" for h in alive)

        rows = [hit_dict(i, h) for i, h in enumerate(ranked, 1)]
        with open(self.csv_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["rank", "ip", "ping_ms", "tls_ms", "jitter_ms", "loss_pct",
                        "speed_mbps", "colo", "city", "verified", "first_seen"])
            for r in rows:
                w.writerow([r["rank"], r["ip"], r["ping_ms"], r["tls_ms"],
                            "" if r["jitter_ms"] is None else r["jitter_ms"],
                            "" if r["loss_pct"] is None else r["loss_pct"],
                            "" if r["speed_mbps"] is None else r["speed_mbps"],
                            r["colo"], r["city"], "yes" if r["verified"] else "no", r["first_seen"]])

        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(build_report(meta, rows), f, indent=2)
        return len(alive)


def build_report(meta, rows):
    return {"tool": "CF-Scanner Pro", "version": __version__,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"), **meta, "results": rows}


def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data, [hit_from_dict(d) for d in data.get("results", [])]
