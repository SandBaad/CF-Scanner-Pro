"""Single-IP probe: TCP connect -> TLS handshake with SNI -> optional HTTP trace."""
import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional

logging.getLogger("asyncio").setLevel(logging.CRITICAL)


@dataclass
class Hit:
    ip: str
    tcp: int                      # ms until TCP connected
    tls: int                      # ms until TLS handshake finished
    colo: str                     # Cloudflare data-center code, "-" if unknown
    seen: str                     # wall-clock time of the hit
    median: Optional[int] = None  # filled by verification
    loss: Optional[float] = None  # 0.0 .. 1.0, filled by verification


class Prober:
    def __init__(self, sni, port=443, timeout=2.0, verify_cert=True, http_check=True):
        self.sni = sni
        self.port = port
        self.timeout = float(timeout)
        self.http_check = http_check

        # Built ONCE and shared by every connection.
        if verify_cert:
            # Python matches the certificate against server_hostname (the SNI),
            # not the IP, so verification works when connecting to a raw IP.
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        self.ctx = ctx

        self.request = (
            "GET /cdn-cgi/trace HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

    @staticmethod
    def _left(deadline):
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise asyncio.TimeoutError
        return remaining

    async def probe(self, ip):
        """Returns (Hit, None) on success or (None, failed_stage)."""
        loop = asyncio.get_running_loop()
        start = time.perf_counter()
        deadline = start + self.timeout
        stage = "tcp"
        sock = writer = None
        own_sock = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, (ip, self.port)), self._left(deadline))
            tcp_ms = (time.perf_counter() - start) * 1000

            stage = "tls"
            own_sock = False  # from here the transport owns and closes the socket
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=sock, ssl=self.ctx, server_hostname=self.sni),
                self._left(deadline),
            )
            tls_ms = (time.perf_counter() - start) * 1000

            colo = "-"
            if self.http_check:
                stage = "http"
                colo = await self._trace(reader, writer, deadline)
                if colo is None:
                    return None, "http"

            return Hit(ip, round(tcp_ms), round(tls_ms), colo, time.strftime("%H:%M:%S")), None
        except ssl.SSLCertVerificationError:
            return None, "cert"
        except (OSError, ValueError, EOFError, asyncio.TimeoutError):
            return None, stage
        finally:
            if writer is not None:
                writer.transport.abort()  # skip the slow TLS close_notify dance
            elif own_sock and sock is not None:
                sock.close()

    async def _trace(self, reader, writer, deadline):
        """Requests /cdn-cgi/trace and returns the colo code, or None."""
        writer.write(self.request)
        await asyncio.wait_for(writer.drain(), self._left(deadline))
        buf = b""
        while len(buf) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), self._left(deadline))
            if not chunk:
                break
            buf += chunk
            i = buf.find(b"\ncolo=")
            if i != -1 and buf.find(b"\n", i + 1) != -1:
                break

        if not buf.startswith(b"HTTP/1.1 200"):
            return None
        i = buf.find(b"\ncolo=")
        if i == -1:
            return None
        j = buf.find(b"\n", i + 1)
        colo = buf[i + 6 : j if j != -1 else None].decode("ascii", "ignore").strip()
        return colo or None
