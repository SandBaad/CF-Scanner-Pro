"""End-to-end tests against a local TLS server that imitates a Cloudflare edge."""
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cfscan import ranges  # noqa: E402
from cfscan.engine import Hit, Prober, SpeedTester, make_context, parse_trace  # noqa: E402
from cfscan.output import ResultSink, load_report  # noqa: E402
from cfscan.scanner import ScanState, Scanner, rank_key  # noqa: E402
from cfscan.term import Theme  # noqa: E402
from cfscan.tui import Dashboard, hit_table, render_summary  # noqa: E402

SNI = "edge.test"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


# ------------------------------------------------------------------ fixtures

@pytest.fixture(scope="session")
def cert(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("cert")
    key, crt = str(d / "key.pem"), str(d / "crt.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-keyout", key, "-out", crt, "-subj", f"/CN={SNI}",
                    "-addext", f"subjectAltName=DNS:{SNI}"], check=True, capture_output=True)
    return key, crt


class FakeEdge:
    """TLS server on 127.0.0.1 serving /cdn-cgi/trace and /__down?bytes=N."""

    def __init__(self, key, crt, colo="FRA", host_override=None):
        import ssl
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(crt, key)
        self.colo, self.host_override = colo, host_override
        self.loop = asyncio.new_event_loop()
        self.port = None
        ready = threading.Event()
        threading.Thread(target=self._run, args=(ready,), daemon=True).start()
        ready.wait(5)

    def _run(self, ready):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self.ctx))
        self.port = server.sockets[0].getsockname()[1]
        ready.set()
        self.loop.run_forever()

    async def _handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line = head.split(b"\r\n")[0].decode()
            host = re.search(rb"(?i)\r\nhost: ([^\r]+)", head).group(1).decode()
            path = line.split()[1]
            if path == "/cdn-cgi/trace":
                body = (f"fl=1\nh={self.host_override or host}\nip=1.2.3.4\nts=1\n"
                        f"colo={self.colo}\nhttp=http/1.1\nloc=DE\n").encode()
            elif path.startswith("/__down"):
                body = b"x" * int(path.split("bytes=")[1])
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
            writer.write(body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()


@pytest.fixture(scope="session")
def edge(cert):
    return FakeEdge(*cert)


def run(coro):
    return asyncio.run(coro)


def prober(edge, cert, **kw):
    return Prober(SNI, edge.port, timeout=kw.pop("timeout", 3), ctx=make_context(True, cafile=cert[1]), **kw)


# ------------------------------------------------------------------ engine

def test_parse_trace():
    ok = b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nfl=1\nh=edge.test\ncolo=ams\n"
    assert parse_trace(ok, "edge.test") == "AMS"
    assert parse_trace(ok.replace(b"200 OK", b"403 Forbidden"), "edge.test") is None
    assert parse_trace(ok, "other.test") is None  # host mismatch = hijack
    assert parse_trace(b"HTTP/1.1 200 OK\r\n\r\n<html>blocked</html>", "edge.test") is None
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2a\r\nfl=1\nh=edge.test\ncolo=IST\n\r\n0\r\n\r\n"
    assert parse_trace(chunked, "edge.test") == "IST"


def test_probe_success(edge, cert):
    hit, stage = run(prober(edge, cert).probe("127.0.0.1"))
    assert stage is None and hit.colo == "FRA" and hit.ip == "127.0.0.1"
    assert 0 <= hit.tcp <= hit.tls


def test_probe_tcp_fail(edge, cert):
    hit, stage = run(prober(edge, cert, timeout=1).probe("127.0.0.2"))
    assert hit is None and stage == "tcp"


def test_probe_cert_mismatch(edge, cert):
    p = Prober("wrong.test", edge.port, timeout=3, ctx=make_context(True, cafile=cert[1]))
    assert run(p.probe("127.0.0.1")) == (None, "cert")


def test_probe_untrusted_cert(edge):
    # Real system CAs don't trust our self-signed cert: must fail, not pass.
    p = Prober(SNI, edge.port, timeout=3)
    assert run(p.probe("127.0.0.1"))[1] == "cert"
    p = Prober(SNI, edge.port, timeout=3, verify_cert=False)
    assert run(p.probe("127.0.0.1"))[1] is None


def test_probe_hijacked_trace(cert):
    bad = FakeEdge(*cert, host_override="evil.test")
    p = Prober(SNI, bad.port, timeout=3, ctx=make_context(True, cafile=cert[1]))
    assert run(p.probe("127.0.0.1")) == (None, "http")


def test_speed(edge, cert):
    st = SpeedTester(f"https://{SNI}:{edge.port}/__down?bytes=400000", ctx=make_context(True, cafile=cert[1]))
    mbps, err = run(st.run("127.0.0.1"))
    assert err == "" and mbps > 1
    st = SpeedTester(f"https://{SNI}:{edge.port}/missing", ctx=make_context(True, cafile=cert[1]))
    assert run(st.run("127.0.0.1")) == (None, "HTTP 404")
    st = SpeedTester(f"https://{SNI}:{edge.port}/__down?bytes=1000", ctx=make_context(True, cafile=cert[1]))
    assert run(st.run("127.0.0.1")) == (None, "too slow")  # too little data to measure


# ------------------------------------------------------------------ scanner

def cfg(**kw):
    base = dict(sample=0, expand_blocks=0, expand=0, verify_top=5, verify_rounds=3, speed_top=3,
                speed_par=1, concurrency=16, target=0, mode="full", sni=SNI, port=0, timeout=1.0, seed=1)
    base.update(kw)
    return base


def test_full_scan_pipeline(edge, cert, tmp_path):
    state = ScanState()
    sink = ResultSink(str(tmp_path))
    state.sink = sink
    speed = SpeedTester(f"https://{SNI}:{edge.port}/__down?bytes=300000", ctx=make_context(True, cafile=cert[1]))
    blocks = [(int.from_bytes(bytes([127, 0, 0, 0]), "big"), 8)]  # 127.0.0.1-6
    sc = Scanner(cfg(port=edge.port), prober(edge, cert, timeout=1), state, blocks=blocks, speed=speed)
    run(sc.run())
    assert state.phases == ["Scan", "Verify", "Speed"]
    assert state.tested == 6 and state.found == 1 and state.fails["tcp"] == 5
    h = state.hits["127.0.0.1"]
    assert h.loss == 0 and h.hs is not None and h.jitter is not None and h.speed > 0

    saved = sink.finalize(state.ranked(), {"sni": SNI})
    assert saved == 1
    assert open(sink.ips_path).read().split() == ["127.0.0.1"]
    data, hits = load_report(sink.json_path)
    assert data["results"][0]["colo"] == "FRA" and hits[0].speed == h.speed


def test_list_check_and_colo_filter(edge, cert):
    state = ScanState(colos=["AMS"])
    sc = Scanner(cfg(port=edge.port, speed_top=0), prober(edge, cert, timeout=1), state,
                 targets=["127.0.0.1", "127.0.0.3"])
    run(sc.run())
    assert state.tested == 2 and state.found == 0 and state.filtered == 1


def test_speed_failure_vs_blocked_host(edge, cert, monkeypatch):
    dead = SpeedTester("https://nowhere.test:1/x", ctx=make_context(True, cafile=cert[1]), timeout=1)
    # One failure, host not declared blocked -> the IP is penalised.
    state = ScanState()
    run(Scanner(cfg(port=edge.port), prober(edge, cert, timeout=1), state,
                targets=["127.0.0.1"], speed=dead).run())
    assert state.hits["127.0.0.1"].speed_err == "tcp" and not state.speed_blocked
    # Host unreachable for everyone -> nobody is penalised.
    import cfscan.scanner as sc_mod
    monkeypatch.setattr(sc_mod, "SPEED_GIVE_UP", 1)
    state = ScanState()
    run(Scanner(cfg(port=edge.port), prober(edge, cert, timeout=1), state,
                targets=["127.0.0.1"], speed=dead).run())
    assert state.speed_blocked == "tcp" and state.hits["127.0.0.1"].speed_err == ""


def test_rank_order():
    a = Hit("1.1.1.1", 50, 100); a.apply_rounds([50] * 5, [100] * 5, 5)
    b = Hit("1.1.1.2", 40, 80); b.apply_rounds([40, 40], [80, 80], 5)          # 60% loss
    c = Hit("1.1.1.3", 30, 60)                                                  # not verified
    d = Hit("1.1.1.4", 60, 120); d.apply_rounds([], [], 5)                       # dead
    e = Hit("1.1.1.5", 70, 140); e.apply_rounds([70] * 5, [140] * 5, 5); e.speed = 40.0
    order = [h.ip for h in sorted([a, b, c, d, e], key=rank_key)]
    assert order == ["1.1.1.5", "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"]


def test_expand_targets():
    assert ranges.expand_targets(["1.2.3.4", "10.0.0.0/30", "1.2.3.4"]) == ["1.2.3.4", "10.0.0.1", "10.0.0.2"]
    with pytest.raises(ValueError):
        ranges.expand_targets(["nope"])
    blocks = ranges.to_blocks(ranges.parse_ranges(ranges.BUILTIN_RANGES))
    assert len(blocks) > 5000


# ------------------------------------------------------------------ UI

def _state_with_hits(n=30):
    st = ScanState()
    st.phases = ["Discovery", "Expansion", "Verify", "Speed"]
    st.begin_phase("Verify", 200)
    st.phase_done = 120
    for i in range(n):
        h = Hit(f"104.16.{i}.{i + 7}", 60 + i * 9, 120 + i * 13, "FRA" if i % 2 else "XYZ")
        if i % 3 == 0:
            h.apply_rounds([60, 61, 65], [120, 125, 160], 3 + i % 2)
        if i % 4 == 0:
            h.speed = 12.5 * (i + 1)
        st.add_hit(h)
        st.add_fail("tcp")
    st.log("a very long log line " * 10, "warn")
    return st


@pytest.mark.parametrize("w,h", [(160, 50), (120, 40), (99, 30), (80, 24), (60, 20), (44, 14), (30, 10)])
@pytest.mark.parametrize("unicode", [True, False])
def test_dashboard_fits(w, h, unicode):
    th = Theme(color=True, unicode=unicode)
    c = dict(sni="sub.example-domain.com", mode="smart", concurrency=200, timeout=2.5, port=443)
    lines = Dashboard(_state_with_hits(), c, th, "working_ips.txt").render(w, h)
    assert len(lines) <= max(h, 14)
    for ln in lines:
        assert len(ANSI.sub("", ln)) == max(w, 44), repr(ANSI.sub("", ln))


def test_summary_and_table():
    th = Theme(color=False, unicode=True)
    st = _state_with_hits()
    st.finish()
    out = render_summary(th, st, st.ranked(), 100)
    assert any("Scan complete" in ln for ln in out)
    assert any("Frankfurt" in ln for ln in out)
    for ln in out[: out.index("") if "" in out else len(out)]:
        assert len(ln) == 100
    for width in (30, 50, 90):
        for ln in hit_table(th, st.top(5), width):
            assert len(ln) == width


# ------------------------------------------------------------------ CLI

def cli(*args, cwd=None):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, CFSCAN_CONFIG=os.path.join(cwd or root, "cfg.json"), NO_COLOR="1")
    return subprocess.run([sys.executable, os.path.join(root, "main.py"), *args],
                          capture_output=True, text=True, cwd=cwd, env=env, timeout=60)


def test_cli_basics(tmp_path):
    r = cli(cwd=str(tmp_path))
    assert r.returncode == 0 and "cfscan scan" in r.stdout
    assert cli("--version", cwd=str(tmp_path)).stdout.startswith("CF-Scanner Pro")
    r = cli("ranges", cwd=str(tmp_path))
    assert r.returncode == 0 and "104.16.0.0/13" in r.stdout
    r = cli("scan", "not a domain", cwd=str(tmp_path))
    assert r.returncode == 2 and "not a valid domain" in r.stderr


def test_cli_test_json(tmp_path):
    # 127.0.0.2:9 refuses -> one failed IP, exit code 1, valid JSON.
    r = cli("test", "127.0.0.2", "--sni", "x.example.com", "-p", "9", "-t", "1", "--rounds", "1", "--json",
            cwd=str(tmp_path))
    data = json.loads(r.stdout)
    assert r.returncode == 1 and data["tested"] == 1 and data["results"] == []


def test_cli_show(tmp_path):
    sink = ResultSink(str(tmp_path))
    h = Hit("1.2.3.4", 50, 90, "AMS"); h.apply_rounds([50, 52], [90, 95], 2); h.speed = 33.3
    sink.finalize([h], {"sni": SNI, "mode": "smart", "tested": 10, "found": 1})
    r = cli("show", str(tmp_path), cwd=str(tmp_path))
    assert r.returncode == 0 and "1.2.3.4" in r.stdout and "Amsterdam" in r.stdout
    assert cli("show", "--ips", str(tmp_path), cwd=str(tmp_path)).stdout.split() == ["1.2.3.4"]


def test_cli_legacy_flags(tmp_path):
    r = cli("--sni", "bad", cwd=str(tmp_path))
    assert r.returncode == 2 and "not a valid domain" in r.stderr


def test_only_single_width_glyphs():
    """Every character the UI draws must be one cell wide in any monospace font."""
    import unicodedata
    allowed = lambda ch: ord(ch) < 0x100 or 0x2500 <= ord(ch) <= 0x259F  # noqa: E731
    st = _state_with_hits()
    for unicode in (True, False):
        th = Theme(color=False, unicode=unicode)
        c = dict(sni="sub.example.com", mode="smart", concurrency=200, timeout=2.5, port=443)
        frames = Dashboard(st, c, th, "working_ips.txt").render(120, 40)
        st2 = _state_with_hits(); st2.stopping = True; st2.finish()
        frames += render_summary(th, st2, st2.ranked(), 100)
        frames += Dashboard(st2, c, th).render(70, 30)
        bad = {ch for ln in frames for ch in ANSI.sub("", ln) if not allowed(ch)}
        assert not bad, f"wide/ambiguous glyphs: {[unicodedata.name(ch, hex(ord(ch))) for ch in bad]}"


def test_slow_download_ranks_below_faster():
    fast_hs = Hit("1.0.0.1", 5, 10); fast_hs.apply_rounds([5] * 3, [10] * 3, 3); fast_hs.speed = 1.5
    ok = Hit("1.0.0.2", 30, 56); ok.apply_rounds([30] * 3, [56] * 3, 3); ok.speed = 9.0
    untested = Hit("1.0.0.3", 20, 40); untested.apply_rounds([20] * 3, [40] * 3, 3)
    failed = Hit("1.0.0.4", 10, 20); failed.apply_rounds([10] * 3, [20] * 3, 3); failed.speed_err = "timeout"
    order = [h.ip for h in sorted([failed, untested, fast_hs, ok], key=rank_key)]
    assert order == ["1.0.0.2", "1.0.0.1", "1.0.0.3", "1.0.0.4"]
