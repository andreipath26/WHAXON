"""Metasploit RPC wrapper.

Reads configuration from environment variables:

    WHAXON_MSF_HOST      default 127.0.0.1
    WHAXON_MSF_PORT      default 55553
    WHAXON_MSF_USER      default msf
    WHAXON_MSF_PASS      default test123
    WHAXON_MSF_SSL       default "0" (use "1" or "true" to enable)

The client is lazy: it doesn't connect until first use. If the daemon
isn't running, `MSFUnavailableError` is raised — callers can catch it
and degrade gracefully.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


class MSFUnavailableError(RuntimeError):
    """Raised when the Metasploit RPC daemon can't be reached."""


@dataclass
class MSFConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    user: str = "msf"
    password: str = "test123"
    ssl: bool = False
    timeout: float = 5.0

    @classmethod
    def from_env(cls) -> "MSFConfig":
        def _bool(v: str) -> bool:
            return v.strip().lower() in ("1", "true", "yes", "on")
        return cls(
            host=os.environ.get("WHAXON_MSF_HOST", "127.0.0.1"),
            port=int(os.environ.get("WHAXON_MSF_PORT", "55553")),
            user=os.environ.get("WHAXON_MSF_USER", "msf"),
            password=os.environ.get("WHAXON_MSF_PASS", "test123"),
            ssl=_bool(os.environ.get("WHAXON_MSF_SSL", "0")),
            timeout=float(os.environ.get("WHAXON_MSF_TIMEOUT", "5")),
        )

    def display(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


class MSFClient:
    """Thin wrapper around pymetasploit3.MsfRpcClient.

    Attributes:
        config: the MSFConfig in use
        client: the underlying MsfRpcClient, or None if not connected yet
    """

    def __init__(self, config: MSFConfig | None = None) -> None:
        self.config = config or MSFConfig.from_env()
        self._client: Any | None = None

    # ---- connection ----

    def connect(self) -> Any:
        """Connect and cache the client. Raises MSFUnavailableError on failure."""
        if self._client is not None:
            return self._client

        self._probe_or_raise()

        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError as e:
            raise MSFUnavailableError(
                "pymetasploit3 is not installed. "
                "Run: pip install -e '.[metasploit]'"
            ) from e

        try:
            self._client = MsfRpcClient(
                self.config.password,
                server=self.config.host,
                port=self.config.port,
                ssl=self.config.ssl,
            )
        except Exception as e:
            raise MSFUnavailableError(
                f"could not reach Metasploit RPC at {self.config.display()}: {e}"
            ) from e
        return self._client

    def _probe_or_raise(self) -> None:
        """Quick socket-level check. Raises MSFUnavailableError with a clear message."""
        import socket
        import ssl as _ssl

        timeout = max(1.0, min(5.0, self.config.timeout))

        try:
            sock = socket.create_connection(
                (self.config.host, self.config.port), timeout=timeout,
            )
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            raise MSFUnavailableError(
                f"cannot reach {self.config.host}:{self.config.port} "
                f"({type(e).__name__}). Is msfrpcd running?"
            ) from e

        try:
            if self.config.ssl:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                try:
                    ctx.wrap_socket(sock, server_hostname=self.config.host)
                except (_ssl.SSLError, TimeoutError, OSError) as e:
                    raise MSFUnavailableError(
                        f"SSL handshake failed on {self.config.display()}. "
                        f"The daemon is probably running WITHOUT SSL \u2014 "
                        f"unset WHAXON_MSF_SSL or start msfrpcd with -S."
                    ) from e
            else:
                try:
                    sock.sendall(b"GET /api/ HTTP/1.0\r\n\r\n")
                    sock.settimeout(timeout)
                except OSError:
                    pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def is_up(self) -> bool:
        """Return True if the daemon is reachable."""
        try:
            self.connect()
            return True
        except MSFUnavailableError:
            return False

    def disconnect(self) -> None:
        self._client = None

    # ---- info ----

    def version(self) -> str:
        c = self.connect()
        info = c.core.version
        if isinstance(info, dict):
            return str(info.get("version", "?"))
        return str(info)

    def module_counts(self) -> dict[str, int]:
        c = self.connect()
        return {
            "exploits": len(c.modules.exploits),
            "auxiliary": len(c.modules.auxiliary),
            "post": len(c.modules.post),
            "payloads": len(c.modules.payloads),
        }

    # ---- sessions ----

    def sessions(self) -> dict[str, dict]:
        """Return a mapping of session-id -> session info dict."""
        c = self.connect()
        try:
            raw = c.sessions.list
        except Exception:
            return {}
        if isinstance(raw, dict):
            return {str(k): dict(v) if isinstance(v, dict) else {"info": v}
                    for k, v in raw.items()}
        return {}

    def session_write(self, session_id: str, command: str) -> None:
        """Send a command to a session."""
        c = self.connect()
        sess = c.sessions.session(str(session_id))
        sess.write(command)

    def session_read(self) -> str:
        """Read pending output from the last session used. Empty if nothing."""
        c = self.connect()
        try:
            # pymetasploit3 tracks the last-session target on MsfRpcClient
            return c.sessions.session("1").read() if "1" in c.sessions.list else ""
        except Exception:
            return ""

    # ---- session I/O ----

    def session_exec(self, session_id: str, command: str, timeout: float = 15.0) -> str:
        """Send a command to a session and return the accumulated output.

        pymetasploit3's read() is not streaming — we poll it repeatedly
        and stop when we've seen output then a quiet period.
        """
        import time
        c = self.connect()
        try:
            sess = c.sessions.session(str(session_id))
        except Exception as e:
            return f"[error] session {session_id}: {e}\n"

        try:
            sess.write(command)
        except Exception as e:
            return f"[error] write failed: {e}\n"

        deadline = time.monotonic() + timeout
        chunks: list[str] = []
        quiet = 0

        while time.monotonic() < deadline:
            time.sleep(0.25)
            try:
                data = sess.read()
            except Exception:
                data = ""
            if data:
                chunks.append(data)
                quiet = 0
            else:
                quiet += 1
                # Stop after ~1s of silence if we already got output
                if chunks and quiet >= 4:
                    break
                # Stop after ~5s of total silence
                if quiet >= 20:
                    break

        return "".join(chunks) if chunks else "(no output)"


    # ---- module execution ----

    def module_options(self, module_type: str, module_name: str) -> dict:
        c = self.connect()
        mod = c.modules.use(module_type, module_name)
        return dict(mod.options)

    def execute(
        self,
        module_type: str,
        module_name: str,
        options: dict,
        payload: str | None = None,
    ) -> dict:
        """Execute a module through an RPC console.

        pymetasploit3's module.execute() does not reliably apply options
        for handler/exploit modules (mod.options is a list; mod[KEY]=v
        raises KeyError for payload-derived options). Driving a real
        msfconsole session over RPC is the robust path.
        """
        import time, re as _re
        c = self.connect()
        console = c.consoles.console()
        cmds = [f"use {module_type}/{module_name}"]
        if payload:
            cmds.append(f"set PAYLOAD {payload}")
        for k, v in (options or {}).items():
            if k == "PAYLOAD":
                continue
            cmds.append(f"set {k} {v}")
        cmds.append("run -j")
        cmds.append("jobs -l")
        for cmd in cmds:
            console.write(cmd)
        time.sleep(8)
        out = console.read().get("data", "")
        job_id = None
        for line in out.splitlines():
            m = _re.search(r"Exploit running as background job (\d+)", line)
            if m:
                job_id = int(m.group(1))
                break
        return {"job_id": job_id, "console_output": out}
