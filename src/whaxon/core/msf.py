"""Metasploit RPC wrapper.

Reads configuration from environment variables:

    WHAXON_MSF_HOST      default 127.0.0.1
    WHAXON_MSF_PORT      default 55553
    WHAXON_MSF_USER      default msf
    WHAXON_MSF_PASS      required; no built-in default
    WHAXON_MSF_SSL       default "0"; non-loopback RPC requires verified TLS

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
    password: str = ""
    ssl: bool = False
    timeout: float = 5.0

    @classmethod
    def from_env(cls) -> MSFConfig:
        def _bool(v: str) -> bool:
            return v.strip().lower() in ("1", "true", "yes", "on")
        return cls(
            host=os.environ.get("WHAXON_MSF_HOST", "127.0.0.1"),
            port=int(os.environ.get("WHAXON_MSF_PORT", "55553")),
            user=os.environ.get("WHAXON_MSF_USER", "msf"),
            password=os.environ.get("WHAXON_MSF_PASS", ""),
            ssl=_bool(os.environ.get("WHAXON_MSF_SSL", "0")),
            timeout=float(os.environ.get("WHAXON_MSF_TIMEOUT", "5")),
        )

    def display(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


def _verified_rpc_post(url, payload, headers, *, timeout, ca_bundle=None):
    """Send a pymetasploit3 RPC request with certificate verification enabled."""
    import requests

    return requests.post(
        url,
        data=payload,
        headers=headers,
        verify=ca_bundle or True,
        timeout=timeout,
    )


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

    def _bounded_timeout(self) -> float:
        """Respect configured RPC latency while keeping a finite upper bound."""
        return max(1.0, min(60.0, float(self.config.timeout)))

    def _validate_transport(self) -> None:
        """Never send RPC credentials over plaintext to a non-loopback host."""
        import ipaddress

        host = str(self.config.host).strip().strip("[]").lower().rstrip(".")
        loopback = host == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
        if not loopback and not self.config.ssl:
            raise MSFUnavailableError(
                "refusing plaintext Metasploit RPC to a non-loopback host; "
                "enable verified TLS with WHAXON_MSF_SSL=1 and configure "
                "WHAXON_MSF_CA_BUNDLE for a private CA"
            )

    def connect(self) -> Any:
        """Connect and cache the client. Raises MSFUnavailableError on failure."""
        if self._client is not None:
            return self._client

        self._validate_transport()
        if not self.config.password:
            raise MSFUnavailableError(
                "WHAXON_MSF_PASS is not configured; refusing Metasploit RPC authentication"
            )
        self._probe_or_raise()

        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError as e:
            raise MSFUnavailableError(
                "pymetasploit3 is not installed. "
                "Run: pip install -e '.[metasploit]'"
            ) from e

        timeout = self._bounded_timeout()
        ca_bundle = os.environ.get("WHAXON_MSF_CA_BUNDLE") or None

        class _VerifiedMsfRpcClient(MsfRpcClient):
            """Override pymetasploit3's insecure verify=False HTTP transport."""

            def post_request(self, url, payload):
                return _verified_rpc_post(
                    url, payload, self.headers,
                    timeout=(timeout, timeout), ca_bundle=ca_bundle,
                )

        try:
            self._client = _VerifiedMsfRpcClient(
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

        timeout = self._bounded_timeout()

        try:
            sock = socket.create_connection(
                (self.config.host, self.config.port), timeout=timeout,
            )
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            raise MSFUnavailableError(
                f"cannot reach {self.config.host}:{self.config.port} "
                f"({type(e).__name__}). Is msfrpcd running?"
            ) from e

        try:
            if self.config.ssl:
                ca_bundle = os.environ.get("WHAXON_MSF_CA_BUNDLE") or None
                ctx = _ssl.create_default_context(cafile=ca_bundle)
                # Keep hostname and certificate verification enabled. For a
                # private CA, configure WHAXON_MSF_CA_BUNDLE instead of
                # silently disabling TLS authentication.
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

    def sessions(self, *, strict: bool = False) -> dict[str, dict]:
        """Return a mapping of session-id -> session info dict."""
        c = self.connect()
        try:
            raw = c.sessions.list
        except Exception:
            if strict:
                raise
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

    def execute_rpc(
        self,
        module_type: str,
        module_name: str,
        options: dict,
        payload: str | None = None,
        timeout_s: float = 30.0,
    ) -> dict:
        """Execute a validated module through Metasploit's structured RPC API.

        This avoids parsing terminal output to determine whether a job started.
        Option values are validated with the same restrictions as console dispatch.
        """
        import re

        if module_type not in {"exploit", "auxiliary", "post"}:
            raise ValueError("unsupported Metasploit module type")
        if (not isinstance(module_name, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", module_name)
                or any(part in {".", ".."} for part in module_name.split("/"))):
            raise ValueError("invalid Metasploit module path")

        def safe_value(value, label):
            text = str(value)
            if not text or ";" in text or any(ord(ch) < 32 for ch in text):
                raise ValueError(f"invalid Metasploit {label}: command delimiter/control character")
            return text

        if payload is not None:
            payload = safe_value(payload, "payload")
        validated_options = {}
        for key, value in (options or {}).items():
            if key == "PAYLOAD":
                continue
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
                raise ValueError("invalid Metasploit option name")
            validated_options[key] = safe_value(value, f"option {key}")
        if not 0.1 <= float(timeout_s) <= 180.0:
            raise ValueError("Metasploit dispatch timeout must be between 0.1 and 180 seconds")

        run_options = dict(validated_options)
        if payload:
            run_options["PAYLOAD"] = payload
        result = self.connect().call(
            "module.execute", [module_type, module_name, run_options],
        )
        if not isinstance(result, dict):
            raise RuntimeError("Metasploit module.execute returned an invalid response")
        return result

    def execute(
        self,
        module_type: str,
        module_name: str,
        options: dict,
        payload: str | None = None,
        timeout_s: float = 30.0,
    ) -> dict:
        """Execute a validated module and poll for its job without fixed sleeps.

        Console input is a command language, not an argv vector. Reject
        delimiters/control characters so option values cannot inject commands.
        """
        import re
        import time

        if module_type not in {"exploit", "auxiliary", "post"}:
            raise ValueError("unsupported Metasploit module type")
        if (not isinstance(module_name, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", module_name)
                or any(part in {".", ".."} for part in module_name.split("/"))):
            raise ValueError("invalid Metasploit module path")

        def safe_value(value, label):
            text = str(value)
            if not text or ";" in text or any(ord(ch) < 32 for ch in text):
                raise ValueError(f"invalid Metasploit {label}: command delimiter/control character")
            return text

        if payload is not None:
            payload = safe_value(payload, "payload")
        validated_options = {}
        for key, value in (options or {}).items():
            if key == "PAYLOAD":
                continue
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
                raise ValueError("invalid Metasploit option name")
            validated_options[key] = safe_value(value, f"option {key}")

        if not 0.1 <= float(timeout_s) <= 180.0:
            raise ValueError("Metasploit dispatch timeout must be between 0.1 and 180 seconds")

        c = self.connect()
        console = c.consoles.console()
        commands = [f"use {module_type}/{module_name}"]
        if payload:
            commands.append(f"set PAYLOAD {payload}")
        commands.extend(f"set {key} {value}" for key, value in validated_options.items())
        commands.extend(("run -j", "jobs -l"))
        for command in commands:
            console.write(command)

        deadline = time.monotonic() + float(timeout_s)
        output_parts: list[str] = []
        job_id = None
        while time.monotonic() < deadline:
            response = console.read() or {}
            chunk = response.get("data", "") if isinstance(response, dict) else str(response)
            if chunk:
                output_parts.append(str(chunk))
            output = "".join(output_parts)
            match = re.search(
                r"(?:Exploit|Post module|Auxiliary module) running as background job ([0-9]+)",
                output,
            )
            if match:
                job_id = int(match.group(1))
                break
            in_jobs = False
            for line in output.splitlines():
                if line.strip() == "Jobs":
                    in_jobs = True
                    continue
                if in_jobs:
                    match = re.match(r" +([0-9]+) +", line)
                    if match:
                        job_id = int(match.group(1))
                        break
                    if line.strip() and not line.strip().startswith("-"):
                        in_jobs = False
            if job_id is not None:
                break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))

        return {"job_id": job_id, "console_output": "".join(output_parts)}
