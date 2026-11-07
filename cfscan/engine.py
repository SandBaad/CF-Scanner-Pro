"""Network probes.

probe():  TCP connect -> TLS handshake with your SNI (certificate checked)
          -> GET /cdn-cgi/trace, which must answer 200, echo your host (h=)
          and name the Cloudflare colo. An IP passes only if every step works.
speed():  a real download through the IP (default: speed.cloudflare.com/__down)
          measured from the first body byte, so DPI throttling shows up.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from statistics import median, pstdev
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

logging.getLogger("asyncio").setLevel(logging.CRITICAL)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
STAGES = ("tcp", "tls", "cert", "http")
DEFAULT_SPEED_HOST = "speed.cloudflare.com"
MIN_SPEED_BYTES = 64 * 1024  # below this a measurement is noise


@dataclass
class Hit:
    ip: str
    tcp: int                        # ms until TCP connected (first sighting)
    tls: int                        # ms until TLS done (first sighting)
    colo: str = "-"                 # Cloudflare data center, "-" if unknown
    seen: str = ""                  # wall-clock time of first sighting
    ping: Optional[int] = None      # median TCP connect over re-tests
    hs: Optional[int] = None        # median TLS-ready time over re-tests
    jitter: Optional[int] = None    # std-dev of TLS-ready time
    loss: Optional[float] = None    # 0..1 over re-tests
    speed: Optional[float] = None   # Mbit/s from the download test
    speed_err: str = ""             # why the download test failed

    @property
    def verified(self):
        return self.loss is not None

    @property
    def alive(self):
        return self.loss is None or self.loss < 1

    @property
    def latency(self):
        return self.hs if self.hs is not None else self.tls

    def apply_rounds(self, tcps: List[float], tlss: List[float], rounds: int):
        self.loss = 1 - len(tlss) / rounds if rounds else None
        if tlss:
            self.ping = round(median(tcps))
            self.hs = round(median(tlss))
            self.jitter = round(pstdev(tlss)) if len(tlss) > 1 else 0
        else:
            self.ping = self.hs = self.jitter = None


class ProbeFail(Exception):
    def __init__(self, stage):
        super().__init__(stage)
        self.stage = stage


def make_context(verify=True, cafile=None):
    if verify:
        ctx = ssl.create_default_context(cafile=cafile)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    return ctx


def _left(deadline):
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise asyncio.TimeoutError
    return remaining


async def open_tls(ip, port, sni, ctx, deadline):
    """Connects and handshakes. Returns (reader, writer, tcp_ms, tls_ms) or raises ProbeFail."""
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), _left(deadline))
    except (OSError, asyncio.TimeoutError):
        sock.close()
        raise ProbeFail("tcp")
    except BaseException:
        sock.close()
        raise
    tcp_ms = (time.perf_counter() - start) * 1000
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(sock=sock, ssl=ctx, server_hostname=sni),
            _left(deadline),
        )
    except ssl.SSLCertVerificationError:
        sock.close()
        raise ProbeFail("cert")
    except (OSError, ValueError, EOFError, asyncio.TimeoutError):
        sock.close()
        raise ProbeFail("tls")
    except BaseException:
        sock.close()
        raise
    return reader, writer, tcp_ms, (time.perf_counter() - start) * 1000


def parse_trace(buf: bytes, sni: str) -> Optional[str]:
    """Validates a /cdn-cgi/trace response and returns the colo, else None."""
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return None
    status = head.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or not status[0].startswith(b"HTTP/") or status[1] != b"200":
        return None
    fields = {}
    for line in body.decode("latin-1").splitlines():
        key, eq, value = line.partition("=")
        if eq:
            fields[key.strip()] = value.strip()
    colo = fields.get("colo", "")
    if not (2 <= len(colo) <= 5 and colo.isalnum()):
        return None
    host = fields.get("h")
    if host and host.lower() != sni.lower():
        return None  # answered for another host: hijacked or transparent proxy
    return colo.upper()


class Prober:
    def __init__(self, sni, port=443, timeout=2.5, verify_cert=True, http_check=True, ctx=None):
        self.sni = sni
        self.port = port
        self.timeout = float(timeout)
        self.http_check = http_check
        self.ctx = ctx or make_context(verify_cert)
        self.request = (
            "GET /cdn-cgi/trace HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"User-Agent: {UA}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

    async def probe(self, ip) -> Tuple[Optional[Hit], Optional[str]]:
        """Returns (Hit, None) when every check passes, else (None, failed_stage)."""
        deadline = time.perf_counter() + self.timeout
        writer = None
        try:
            reader, writer, tcp_ms, tls_ms = await open_tls(ip, self.port, self.sni, self.ctx, deadline)
            colo = "-"
            if self.http_check:
                colo = await self._trace(reader, writer, deadline)
                if colo is None:
                    return None, "http"
            return Hit(ip, round(tcp_ms), round(tls_ms), colo, time.strftime("%H:%M:%S")), None
        except ProbeFail as e:
            return None, e.stage
        except (OSError, ValueError, EOFError, asyncio.TimeoutError):
            return None, "http"
        finally:
            if writer is not None:
                writer.transport.abort()  # skip the slow TLS close_notify dance

    async def _trace(self, reader, writer, deadline):
        writer.write(self.request)
        await asyncio.wait_for(writer.drain(), _left(deadline))
        buf = b""
        while len(buf) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), _left(deadline))
            if not chunk:
                break
            buf += chunk
            i = buf.find(b"\ncolo=")
            if i != -1 and buf.find(b"\n", i + 1) != -1:
                break
        return parse_trace(buf, self.sni)


class SpeedTester:
    """Downloads through one IP and reports Mbit/s (partial downloads still count)."""

    def __init__(self, url=None, size_mb=2.0, timeout=8.0, verify_cert=True, ctx=None):
        if url:
            parts = urlsplit(url if "://" in url else "https://" + url)
            if not parts.hostname:
                raise ValueError(f"bad speed URL: {url}")
            self.host = parts.hostname
            self.port = parts.port or 443
            self.path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        else:
            self.host = DEFAULT_SPEED_HOST
            self.port = 443
            self.path = f"/__down?bytes={int(size_mb * 1_000_000)}"
        self.timeout = float(timeout)
        self.ctx = ctx or make_context(verify_cert)
        self.request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {UA}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

    @property
    def label(self):
        return f"{self.host}{self.path}"

    async def run(self, ip) -> Tuple[Optional[float], str]:
        deadline = time.perf_counter() + self.timeout
        writer = None
        try:
            reader, writer, _, _ = await open_tls(ip, self.port, self.host, self.ctx, deadline)
            writer.write(self.request)
            await asyncio.wait_for(writer.drain(), _left(deadline))

            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = await asyncio.wait_for(reader.read(65536), _left(deadline))
                if not chunk:
                    return None, "closed"
                buf += chunk
                if len(buf) > 65536:
                    return None, "bad reply"
            head, _, body = buf.partition(b"\r\n\r\n")
            status = head.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                code = status[1].decode("ascii", "ignore") if len(status) > 1 else "?"
                return None, f"HTTP {code}"
            want = None
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    try:
                        want = int(value.strip()) - len(body)
                    except ValueError:
                        pass

            start, got = time.perf_counter(), 0
            while want is None or got < want:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), remaining)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                got += len(chunk)
            elapsed = time.perf_counter() - start
            if got < MIN_SPEED_BYTES or elapsed <= 0:
                return None, "too slow"
            return got * 8 / elapsed / 1e6, ""
        except ProbeFail as e:
            return None, e.stage
        except (OSError, ValueError, EOFError, asyncio.TimeoutError):
            return None, "timeout"
        finally:
            if writer is not None:
                writer.transport.abort()
