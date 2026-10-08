"""Tool adapters: per-tool parsing + remediation knowledge."""
from .base import Adapter
from .registry import get_adapter, list_adapters, register

__all__ = ["Adapter", "get_adapter", "list_adapters", "register"]
from . import impacket  # noqa: F401
