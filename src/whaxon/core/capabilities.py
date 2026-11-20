"""Versioned capability manifests and deterministic provider resolution.

A manifest describes what a provider can do; it never grants permission to do it.
Authorization remains a separate policy decision at execution time.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

CAPABILITY_SCHEMA_VERSION = "whaxon.capability.v1"
_READINESS = {
    "registered": 0,
    "installed": 1,
    "smoke_tested": 2,
    "lab_validated": 3,
    "end_to_end_verified": 4,
}
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_NETWORK_EFFECT_MARKERS = (
    "network", "dns", "resolver", "http", "web_request", "socket",
    "outbound", "external_api", "internet", "remote_service", "remote_shell",
    "target_service", "tcp", "udp", "icmp",
)


def requires_network_approval(
    permissions: Iterable[str], side_effects: Iterable[str],
) -> bool:
    """Return whether task metadata includes network access or effects."""
    if isinstance(permissions, str) or isinstance(side_effects, str):
        return True
    try:
        permission_values = tuple(permissions)
        effect_values = tuple(side_effects)
    except TypeError:
        return True
    if any(not isinstance(value, str) for value in (*permission_values, *effect_values)):
        return True
    return any(
        permission.partition(".")[0].casefold() == "network"
        for permission in permission_values
    ) or any(
        marker in effect.casefold()
        for effect in effect_values
        for marker in _NETWORK_EFFECT_MARKERS
    )



class _FrozenDict(dict):
    def __init__(self, value=()):
        dict.__init__(self, ((key, _freeze(item)) for key, item in dict(value).items()))

    def _immutable(self, *args, **kwargs):
        raise TypeError("capability manifest mappings are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable

    def __deepcopy__(self, memo):
        return self


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict(value)
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """Return immutable manifest schema data as ordinary JSON containers."""
    if isinstance(value, dict):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class CapabilityManifest:
    """Declarative, versioned provider capability and execution constraints."""

    capability_id: str
    provider_id: str
    provider_version: str
    transports: tuple[str, ...]
    target_types: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    auth_methods: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    side_effects: tuple[str, ...] = ()
    impact: str = "read_only"
    readiness: str = "registered"
    timeout_s: float = 300.0
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    schema_version: str = CAPABILITY_SCHEMA_VERSION
    scope_mode: str = "network"

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_SCHEMA_VERSION:
            raise ValueError(f"unsupported capability schema: {self.schema_version}")
        if not isinstance(self.scope_mode, str) or self.scope_mode not in {"network", "dns_query", "pinned_network"}:
            raise ValueError(f"unsupported scope mode: {self.scope_mode!r}")
        for name, value in (
            ("capability_id", self.capability_id),
            ("provider_id", self.provider_id),
            ("provider_version", self.provider_version),
        ):
            if not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"invalid {name}: {value!r}")
        if not isinstance(self.transports, (list, tuple)) or not self.transports:
            raise ValueError("at least one execution transport is required")
        if self.readiness not in _READINESS:
            raise ValueError(f"unsupported readiness level: {self.readiness}")
        if self.impact not in {"read_only", "low", "moderate", "high", "critical"}:
            raise ValueError(f"unsupported impact: {self.impact}")
        if not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError("timeout_s must be finite and positive")
        for name in (
            "transports", "target_types", "protocols", "platforms", "auth_methods",
            "permissions", "side_effects", "limitations",
        ):
            original = getattr(self, name)
            if not isinstance(original, (list, tuple)):
                raise ValueError(f"{name} must be an array")
            values = tuple(original)
            if any(not isinstance(item, str) or not item for item in values) or len(values) != len(set(values)):
                raise ValueError(f"{name} must contain unique non-empty values")
            object.__setattr__(self, name, values)
        if not isinstance(self.input_schema, dict) or not isinstance(self.output_schema, dict):
            raise TypeError("input_schema and output_schema must be objects")
        object.__setattr__(self, "input_schema", _freeze(self.input_schema))
        object.__setattr__(self, "output_schema", _freeze(self.output_schema))

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        # Keep legacy manifest fingerprints stable while the default remains network.
        if self.scope_mode == "network":
            value.pop("scope_mode")
        value["input_schema"] = _thaw(self.input_schema)
        value["output_schema"] = _thaw(self.output_schema)
        for name in (
            "transports", "target_types", "protocols", "platforms", "auth_methods",
            "permissions", "side_effects", "limitations",
        ):
            value[name] = list(getattr(self, name))
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CapabilityManifest:
        fields = dict(value)
        for name in (
            "transports", "target_types", "protocols", "platforms", "auth_methods",
            "permissions", "side_effects", "limitations",
        ):
            fields[name] = tuple(fields.get(name) or ())
        return cls(**fields)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CapabilityRequirements:
    """Constraints a task requires from a provider; empty fields are unconstrained."""

    target_type: str = ""
    protocol: str = ""
    platform: str = ""
    auth_method: str = ""
    transport: str = ""
    minimum_readiness: str = "registered"
    allowed_providers: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    maximum_impact: str = ""
    maximum_timeout_s: float | None = None
    required_input_schema: dict[str, Any] | None = None
    required_output_schema: dict[str, Any] | None = None
    allowed_versions: tuple[str, ...] = ()
    allowed_fingerprints: tuple[str, ...] = ()
    allowed_side_effects: tuple[str, ...] | None = None


@dataclass(frozen=True)
class CapabilityResolution:
    manifest: CapabilityManifest
    registry_digest: str
    considered: int
    rejected: tuple[str, ...] = ()


class CapabilityUnavailable(LookupError):
    """No registered provider satisfies the task's declared requirements."""

    def __init__(self, capability_id: str, rejected: tuple[str, ...]) -> None:
        self.capability_id = capability_id
        self.rejected = rejected
        detail = "; ".join(rejected) if rejected else "no providers are registered"
        super().__init__(f"no provider for {capability_id!r}: {detail}")


class CapabilityRegistry:
    """In-memory, deterministic registry; callers persist/version snapshots separately."""

    def __init__(self, store=None) -> None:
        self._store = store
        self._manifests: dict[tuple[str, str, str], CapabilityManifest] = {}
        if store is not None:
            for value in store.list_capability_manifests():
                self.register(CapabilityManifest.from_dict(value), persist=False)

    def register(self, manifest: CapabilityManifest, *, persist: bool = True) -> None:
        if not isinstance(manifest, CapabilityManifest):
            raise TypeError("manifest must be a CapabilityManifest")
        key = (manifest.capability_id, manifest.provider_id, manifest.provider_version)
        existing = self._manifests.get(key)
        if existing is not None and existing.fingerprint != manifest.fingerprint:
            raise ValueError("provider manifest version is immutable")
        if persist and self._store is not None:
            self._store.save_capability_manifest(manifest.to_dict())
        self._manifests[key] = manifest

    def list(self, capability_id: str | None = None) -> list[CapabilityManifest]:
        values = list(self._manifests.values())
        if capability_id is not None:
            values = [item for item in values if item.capability_id == capability_id]
        return sorted(values, key=lambda item: (
            item.capability_id, item.provider_id, item.provider_version,
        ))

    @property
    def digest(self) -> str:
        snapshot = [item.to_dict() for item in self.list()]
        return hashlib.sha256(_canonical(snapshot).encode("utf-8")).hexdigest()

    def resolve(
        self,
        capability_id: str,
        requirements: CapabilityRequirements | None = None,
    ) -> CapabilityResolution:
        requirements = requirements or CapabilityRequirements()
        if requirements.minimum_readiness not in _READINESS:
            raise ValueError(f"unsupported minimum readiness: {requirements.minimum_readiness}")
        if requirements.maximum_impact and requirements.maximum_impact not in (
            "read_only", "low", "moderate", "high", "critical",
        ):
            raise ValueError("unsupported maximum impact")
        if requirements.maximum_timeout_s is not None and (
            isinstance(requirements.maximum_timeout_s, bool)
            or not isinstance(requirements.maximum_timeout_s, (int, float))
            or not math.isfinite(requirements.maximum_timeout_s)
            or requirements.maximum_timeout_s <= 0
        ):
            raise ValueError("maximum_timeout_s must be finite and positive")
        for schema in (requirements.required_input_schema, requirements.required_output_schema):
            if schema is not None and not isinstance(schema, dict):
                raise TypeError("required schemas must be objects")
        if requirements.allowed_side_effects is not None and (
            not isinstance(requirements.allowed_side_effects, (tuple, list))
            or any(not isinstance(item, str) for item in requirements.allowed_side_effects)
        ):
            raise ValueError("allowed_side_effects must be a string sequence")
        for values in (requirements.allowed_versions, requirements.allowed_fingerprints, requirements.allowed_providers):
            if not isinstance(values, (tuple, list)) or any(not isinstance(item, str) for item in values):
                raise ValueError("provider allowlists must be string sequences")
        candidates = self.list(capability_id)
        rejected: list[str] = []
        eligible: list[CapabilityManifest] = []
        for manifest in candidates:
            reason = ""
            if _READINESS[manifest.readiness] < _READINESS[requirements.minimum_readiness]:
                reason = f"{manifest.provider_id}: readiness {manifest.readiness} is below {requirements.minimum_readiness}"
            elif requirements.allowed_providers and manifest.provider_id not in requirements.allowed_providers:
                reason = f"{manifest.provider_id}: provider is not allowlisted"
            elif requirements.allowed_versions and manifest.provider_version not in requirements.allowed_versions:
                reason = f"{manifest.provider_id}: provider version is not allowlisted"
            elif requirements.allowed_fingerprints and manifest.fingerprint not in requirements.allowed_fingerprints:
                reason = f"{manifest.provider_id}: manifest fingerprint is not allowlisted"
            elif requirements.allowed_side_effects is not None and not set(manifest.side_effects).issubset(requirements.allowed_side_effects):
                reason = f"{manifest.provider_id}: side effects exceed the allowed set"
            elif not set(requirements.required_permissions).issubset(manifest.permissions):
                reason = f"{manifest.provider_id}: required permissions are not declared"
            elif requirements.maximum_impact and (
                ("read_only", "low", "moderate", "high", "critical").index(manifest.impact)
                > ("read_only", "low", "moderate", "high", "critical").index(requirements.maximum_impact)
            ):
                reason = f"{manifest.provider_id}: impact exceeds permitted maximum"
            elif requirements.maximum_timeout_s is not None and manifest.timeout_s < requirements.maximum_timeout_s:
                reason = f"{manifest.provider_id}: provider timeout is below required task budget"
            elif requirements.required_input_schema is not None and _canonical(manifest.input_schema) != _canonical(requirements.required_input_schema):
                reason = f"{manifest.provider_id}: incompatible input schema"
            elif requirements.required_output_schema is not None and _canonical(manifest.output_schema) != _canonical(requirements.required_output_schema):
                reason = f"{manifest.provider_id}: incompatible output schema"
            else:
                for field_name in (
                    "target_type", "protocol", "platform", "auth_method", "transport",
                ):
                    required = getattr(requirements, field_name)
                    supported = getattr(manifest, {
                        "target_type": "target_types",
                        "protocol": "protocols",
                        "platform": "platforms",
                        "auth_method": "auth_methods",
                        "transport": "transports",
                    }[field_name])
                    if required and required not in supported:
                        reason = f"{manifest.provider_id}: unsupported {field_name} {required!r}"
                        break
            if reason:
                rejected.append(reason)
            else:
                eligible.append(manifest)
        if not eligible:
            raise CapabilityUnavailable(capability_id, tuple(rejected))
        eligible.sort(key=lambda item: (
            -_READINESS[item.readiness], item.provider_id, item.provider_version,
        ))
        return CapabilityResolution(
            manifest=eligible[0],
            registry_digest=self.digest,
            considered=len(candidates),
            rejected=tuple(rejected),
        )
