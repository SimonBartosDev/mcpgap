"""A recording HTTP/HTTPS proxy that never forwards anything upstream.

This is the sole egress from the sandbox. The seatbelt profile permits exactly
one outbound destination -- this proxy on loopback -- so a package that honours
the proxy is recorded here, and a package that ignores it and connects directly
is denied by the kernel. Either way it does not get out silently, which is the
property that matters.

Only HTTP/1.1 is spoken, deliberately: we advertise no ALPN, so clients fall
back from HTTP/2. That keeps the parser small enough to audit.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from mcpgap.model import ObservedRequest
from mcpgap.proxy.ca import EphemeralCA
from mcpgap.proxy.responses import canned_response

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 32 * 1024 * 1024


@dataclass(slots=True)
class _RawRequest:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes


def _read_until(sock: socket.socket, terminator: bytes, limit: int) -> bytes:
    buf = b""
    while terminator not in buf:
        if len(buf) > limit:
            raise ValueError("header section too large")
        chunk = sock.recv(8192)
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_request(sock: socket.socket) -> tuple[_RawRequest | None, bytes]:
    """Read one HTTP/1.1 request. Returns (request, leftover_bytes)."""
    raw = _read_until(sock, b"\r\n\r\n", _MAX_HEADER_BYTES)
    if not raw or b"\r\n\r\n" not in raw:
        return None, b""
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None, b""
    method, target = parts[0], parts[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    body = rest
    if (encoding := headers.get("transfer-encoding", "").lower()) and "chunked" in encoding:
        while not body.endswith(b"0\r\n\r\n"):
            chunk = sock.recv(8192)
            if not chunk:
                break
            body += chunk
        body = _dechunk(body)
    else:
        length = int(headers.get("content-length", "0") or 0)
        length = min(length, _MAX_BODY_BYTES)
        while len(body) < length:
            chunk = sock.recv(min(8192, length - len(body)))
            if not chunk:
                break
            body += chunk
    return _RawRequest(method, target, headers, body), b""


def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        line, _, rest = data.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2 :]
    return out


class SealedProxy:
    """Records every request the sandboxed process makes, and answers them all."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.ca = EphemeralCA(workdir)
        self.ca_bundle = self.ca.write_ca_bundle()
        self._requests: list[ObservedRequest] = []
        self._active = 0
        self._lock = threading.Lock()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(64)
        self.port: int = self._server.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> SealedProxy:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._server.close()

    @property
    def requests(self) -> tuple[ObservedRequest, ...]:
        with self._lock:
            return tuple(self._requests)

    def wait_idle(self, timeout: float = 5.0, settle: float = 0.05) -> bool:
        """Block until no connection is mid-flight and no new one has arrived.

        Connections are handled on their own threads, so a request can still be
        being parsed at the instant the child process exits. Reading `requests`
        straight after a process ends therefore sometimes misses the last one --
        which showed up as a tool disagreeing with itself across runs, since a
        fire-and-forget request is recorded on some runs and not others.

        Returns False if it gave up waiting, so the caller can treat an
        unquiesced proxy as an incomplete observation rather than a clean one.
        """
        deadline = time.monotonic() + timeout
        stable_since: float | None = None
        last_count = -1
        while time.monotonic() < deadline:
            with self._lock:
                active = self._active
                count = len(self._requests)
            if active == 0 and count == last_count:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= settle:
                    return True
            else:
                stable_since = None
                last_count = count
            time.sleep(0.01)
        return False

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()

    def _record(self, request: ObservedRequest) -> None:
        with self._lock:
            self._requests.append(request)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with self._lock:
            self._active += 1
        try:
            conn.settimeout(30)
            request, _ = _parse_request(conn)
            if request is None:
                return
            if request.method.upper() == "CONNECT":
                self._handle_connect(conn, request.target)
            else:
                self._handle_plain(conn, request)
        except (OSError, ssl.SSLError, ValueError):
            # A malformed or abandoned connection is not itself interesting;
            # what the package tried to send is recorded before we get here.
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            with self._lock:
                self._active -= 1

    def _handle_connect(self, conn: socket.socket, authority: str) -> None:
        host, _, port_text = authority.partition(":")
        port = int(port_text or 443)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        cert_path, key_path = self.ca.leaf_for(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        # No ALPN advertisement, so clients negotiate HTTP/1.1.
        with context.wrap_socket(conn, server_side=True) as tls:
            tls.settimeout(30)
            request, _ = _parse_request(tls)
            if request is None:
                return
            self._respond(tls, host, port, request, scheme="https")

    def _handle_plain(self, conn: socket.socket, request: _RawRequest) -> None:
        target = request.target
        host = request.headers.get("host", "")
        port = 80
        if target.startswith("http://"):
            authority, _, rest = target[len("http://") :].partition("/")
            host = authority
            request.target = "/" + rest
        if ":" in host:
            host, _, port_text = host.partition(":")
            port = int(port_text or 80)
        self._respond(conn, host, port, request, scheme="http")

    def _respond(
        self,
        sock: socket.socket | ssl.SSLSocket,
        host: str,
        port: int,
        request: _RawRequest,
        *,
        scheme: str,
    ) -> None:
        self._record(
            ObservedRequest(
                host=host,
                port=port,
                method=request.method.upper(),
                path=request.target,
                headers=dict(request.headers),
                body=request.body or None,
            )
        )
        status, headers, body = canned_response(host, request.method.upper(), request.target)
        head = [f"HTTP/1.1 {status} OK"]
        head += [f"{k}: {v}" for k, v in headers.items()]
        head += [f"Content-Length: {len(body)}", "Connection: close", "", ""]
        sock.sendall("\r\n".join(head).encode("latin-1") + body)

    def child_env(self) -> dict[str, str]:
        """Environment that routes a Node child through this proxy.

        `--use-env-proxy` is required for Node's built-in fetch (undici), which
        ignores HTTPS_PROXY otherwise. axios -- used by the Postmark SDK --
        honours the variables directly. Both paths matter: the package makes API
        calls through axios and caller-directed attachment fetches through fetch.
        """
        endpoint = f"http://127.0.0.1:{self.port}"
        return {
            "HTTP_PROXY": endpoint,
            "HTTPS_PROXY": endpoint,
            "http_proxy": endpoint,
            "https_proxy": endpoint,
            "NODE_EXTRA_CA_CERTS": str(self.ca_bundle),
            "NODE_OPTIONS": "--use-env-proxy",
        }
