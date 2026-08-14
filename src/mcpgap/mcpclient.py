"""Minimal MCP client over stdio.

Hand-rolled rather than taken from the official SDK, for three reasons:

* **Version skew.** The packages we scan are frozen in time -- the acceptance
  fixture pins `@modelcontextprotocol/sdk ^1.12.1` from 2025 -- while an SDK we
  depended on would keep moving. Negotiating the protocol version ourselves
  means a server we cannot talk to is a diagnosable error rather than a silent
  handshake failure.
* **Evidence.** Every frame in both directions is retained verbatim. A finding
  has to be defensible, and "here is the exact JSON-RPC exchange" is part of it.
* **Dependency surface.** This tool runs code from strangers; its own
  dependency list is one package on purpose.

A failed handshake raises `HandshakeError`. It must never be mistaken for a
server that merely has no tools -- that difference is `cannot_conclude` versus a
clean scan, and collapsing it is the exact failure this project exists to avoid.
"""

from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any

# Newest first. The 2025-06-18 and 2025-03-26 revisions are what current servers
# speak; 2024-11-05 is what the acceptance fixture's SDK generation used.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

CLIENT_INFO = {"name": "mcpgap", "version": "0.0.1"}


class McpError(RuntimeError):
    """Any failure to talk to the server."""


class HandshakeError(McpError):
    """The server never completed `initialize`.

    Distinct from "the server has no tools" on purpose.
    """


@dataclass(slots=True)
class Frame:
    direction: str  # "out" | "in"
    payload: dict[str, Any]


@dataclass
class StdioMcpClient:
    """Speaks JSON-RPC 2.0 over a child process's stdin/stdout."""

    process: subprocess.Popen[bytes]
    timeout: float = 60.0
    frames: list[Frame] = field(default_factory=list)
    protocol_version: str | None = None
    _next_id: int = 1
    _stderr: list[bytes] = field(default_factory=list)
    _stderr_thread: threading.Thread | None = None

    def __post_init__(self) -> None:
        # Drain stderr continuously. The fixture logs progress there, and a full
        # pipe buffer would deadlock the child mid-handshake.
        def drain() -> None:
            stream = self.process.stderr
            if stream is None:
                return
            for line in stream:
                self._stderr.append(line)

        self._stderr_thread = threading.Thread(target=drain, daemon=True)
        self._stderr_thread.start()

    @property
    def stderr_text(self) -> str:
        return b"".join(self._stderr).decode("utf-8", "replace")

    def _send(self, payload: dict[str, Any]) -> None:
        if self.process.stdin is None or self.process.poll() is not None:
            raise McpError(f"server exited before request could be sent: {self.stderr_text[-800:]}")
        self.frames.append(Frame("out", payload))
        self.process.stdin.write(json.dumps(payload).encode() + b"\n")
        self.process.stdin.flush()

    def _read(self) -> dict[str, Any]:
        stream = self.process.stdout
        if stream is None:
            raise McpError("server process has no stdout pipe to read from")
        while True:
            line = stream.readline()
            if not line:
                raise McpError(
                    "server closed stdout without replying. stderr:\n" + self.stderr_text[-2000:]
                )
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                # Servers sometimes print banners to stdout. Skip non-JSON
                # rather than treating it as a protocol error.
                continue
            self.frames.append(Frame("in", payload))
            return payload

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        while True:
            payload = self._read()
            if payload.get("id") != request_id:
                continue  # a notification or an out-of-order reply
            if "error" in payload:
                raise McpError(f"{method} failed: {payload['error']}")
            return payload.get("result", {})

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> str:
        """Complete the handshake, trying each supported protocol version."""
        last: Exception | None = None
        for version in SUPPORTED_PROTOCOL_VERSIONS:
            try:
                result = self.request(
                    "initialize",
                    {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": CLIENT_INFO,
                    },
                )
            except McpError as exc:
                last = exc
                if self.process.poll() is not None:
                    break  # the server is gone; retrying a version is pointless
                continue
            # The server may answer with a different version; that is its choice.
            self.protocol_version = result.get("protocolVersion", version)
            self.notify("notifications/initialized")
            return self.protocol_version
        raise HandshakeError(
            "could not complete the MCP initialize handshake with any of "
            f"{SUPPORTED_PROTOCOL_VERSIONS}. Last error: {last}. "
            f"Server stderr:\n{self.stderr_text[-2000:]}"
        )

    def list_tools(self) -> dict[str, dict[str, Any]]:
        result = self.request("tools/list")
        return {tool["name"]: tool for tool in result.get("tools", [])}

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.terminate()
            self.process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
