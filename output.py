"""Result files: live append during the scan, ranked rewrite at the end."""
import csv


class ResultSink:
    def __init__(self, ips_path="working_ips.txt", csv_path="results.csv"):
        self.ips_path = ips_path
        self.csv_path = csv_path
        self._fh = None

    def add(self, hit):
        # Opened lazily: a scan that finds nothing never wipes previous results.
        if self._fh is None:
            self._fh = open(self.ips_path, "w", encoding="utf-8")
        self._fh.write(hit.ip + "\n")
        self._fh.flush()

    def finalize(self, ranked):
        """Rewrites the files ranked best-first. Returns the number of IPs saved."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if not ranked:
            return 0

        alive = [h for h in ranked if not (h.loss is not None and h.loss >= 1)]
        with open(self.ips_path, "w", encoding="utf-8") as f:
            f.writelines(h.ip + "\n" for h in alive)

        with open(self.csv_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["rank", "ip", "tls_ms", "tcp_ms", "colo", "median_ms", "loss_pct", "seen"])
            for i, h in enumerate(ranked, 1):
                w.writerow([
                    i, h.ip, h.tls, h.tcp, h.colo,
                    "" if h.median is None else h.median,
                    "" if h.loss is None else round(h.loss * 100),
                    h.seen,
                ])
        return len(alive)
