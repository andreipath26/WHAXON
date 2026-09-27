"""Tool adapters: per-tool parsing + remediation knowledge."""
from .base import Adapter
from .registry import get_adapter, register, list_adapters

__all__ = ["Adapter", "get_adapter", "register", "list_adapters"]
from . import impacket  # noqa: F401
