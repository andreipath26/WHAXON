"""Registry: map tool_id -> Adapter instance."""
from __future__ import annotations

from .base import Adapter

_ADAPTERS: dict[str, Adapter] = {}


def register(adapter: Adapter) -> None:
    """Register an adapter instance. Last one wins for a given tool_id."""
    if not adapter.tool_id:
        raise ValueError("Adapter.tool_id must be set")
    _ADAPTERS[adapter.tool_id] = adapter


def get_adapter(tool_id: str) -> Adapter | None:
    return _ADAPTERS.get(tool_id)


def list_adapters() -> list[str]:
    return sorted(_ADAPTERS.keys())


# ---- auto-register built-in adapters when this module is imported ----

def _autoload() -> None:
    """Import known adapter modules so they self-register.

    Silently skips any module that fails to import — this lets us ship
    in-progress adapters without breaking the whole registry.
    """
    import importlib
    for name in ("nmap", "nikto", "burp", "sqlmap", "gobuster", "ffuf", "nuclei", "wpscan", "hashcat", "whois", "dig", "whatweb", "msf"):
        try:
            importlib.import_module(f".{name}", package="whaxon.adapters")
        except ImportError:
            pass
        except Exception as e:
            import sys
            print(f"[adapters] failed to load {name}: {e!r}", file=sys.stderr)


def _discover_plugins() -> None:
    """Discover third-party adapters declared via entry points."""
    import sys
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return
    try:
        eps = entry_points(group='whaxon.adapters')
    except TypeError:
        eps = entry_points().get('whaxon.adapters', [])
    for ep in eps:
        try:
            obj = ep.load()
            adapter = obj() if isinstance(obj, type) else obj
            if isinstance(adapter, Adapter):
                register(adapter)
        except Exception as e:
            print(f'[adapters] plugin {ep.name!r} failed to load: {e!r}', file=sys.stderr)


_autoload()
_discover_plugins()
