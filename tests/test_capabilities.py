from whaxon.core.capabilities import (
    CapabilityManifest,
    CapabilityRegistry,
    CapabilityRequirements,
    CapabilityUnavailable,
)


def _manifest(provider, *, readiness="registered", **kwargs):
    return CapabilityManifest(
        capability_id="network.port_scan",
        provider_id=provider,
        provider_version="1.0.0",
        transports=("local_process",),
        target_types=("hostname", "ip"),
        protocols=("tcp",),
        platforms=("linux",),
        readiness=readiness,
        **kwargs,
    )


def test_capability_resolution_is_deterministic_and_prefers_readiness():
    registry = CapabilityRegistry()
    registry.register(_manifest("provider.z", readiness="installed"))
    registry.register(_manifest("provider.b", readiness="lab_validated"))
    registry.register(_manifest("provider.a", readiness="lab_validated"))
    result = registry.resolve(
        "network.port_scan",
        CapabilityRequirements(target_type="ip", protocol="tcp", platform="linux"),
    )
    assert result.manifest.provider_id == "provider.a"
    assert result.considered == 3
    assert result.registry_digest == registry.digest


def test_capability_resolution_reports_constraint_failures():
    registry = CapabilityRegistry()
    registry.register(_manifest("provider.a"))
    try:
        registry.resolve(
            "network.port_scan",
            CapabilityRequirements(
                protocol="udp", transport="remote_agent",
                minimum_readiness="smoke_tested",
            ),
        )
    except CapabilityUnavailable as exc:
        assert exc.capability_id == "network.port_scan"
        assert len(exc.rejected) == 1
    else:
        raise AssertionError("incompatible provider must not resolve")


def test_capability_provider_version_is_immutable():
    import pytest

    registry = CapabilityRegistry()
    registry.register(_manifest("provider.a", readiness="installed"))
    with pytest.raises(ValueError, match="immutable"):
        registry.register(_manifest("provider.a", readiness="lab_validated"))


def test_capability_manifest_does_not_authorize_execution():
    manifest = _manifest("provider.a", permissions=("network.scan",), impact="moderate")
    assert manifest.permissions == ("network.scan",)
    assert manifest.impact == "moderate"
    assert not hasattr(manifest, "authorized")


def test_capability_manifest_nested_schema_is_immutable():
    import pytest

    schema = {"properties": {"ports": {"enum": [80, 443]}}}
    manifest = _manifest("provider.a", input_schema=schema)
    fingerprint = manifest.fingerprint
    schema["properties"]["ports"]["enum"].append(8080)
    assert manifest.fingerprint == fingerprint
    with pytest.raises(TypeError, match="immutable"):
        manifest.input_schema["properties"]["new"] = {}
    assert manifest.input_schema["properties"]["ports"]["enum"] == (80, 443)


def test_manifest_to_dict_thaws_nested_schema_arrays_for_json_clients():
    manifest = _manifest(
        "provider.a",
        input_schema={
            "type": "object",
            "properties": {"ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["ids"],
        },
    )

    serialized = manifest.to_dict()
    assert serialized["input_schema"]["required"] == ["ids"]
    assert isinstance(serialized["input_schema"]["required"], list)


def test_capability_registry_persists_and_reloads_manifests(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "capabilities.db")
    registry = CapabilityRegistry(store=store)
    manifest = _manifest("provider.persisted", readiness="smoke_tested")
    registry.register(manifest)
    restored = CapabilityRegistry(store=store)
    result = restored.resolve(
        "network.port_scan",
        CapabilityRequirements(minimum_readiness="smoke_tested"),
    )
    assert result.manifest.fingerprint == manifest.fingerprint
    assert restored.digest == registry.digest


def test_store_rejects_manifest_version_mutation(tmp_path):
    import pytest

    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "capability-immutable.db")
    registry = CapabilityRegistry(store=store)
    registry.register(_manifest("provider.immutable", readiness="installed"))
    with pytest.raises(ValueError, match="immutable"):
        registry.register(_manifest("provider.immutable", readiness="lab_validated"))


def test_capability_manifest_rejects_non_finite_timeout():
    import math

    import pytest

    with pytest.raises(ValueError, match="finite"):
        _manifest("provider.nan", timeout_s=math.nan)


def test_resolver_enforces_permissions_impact_and_schema_compatibility():
    import pytest
    registry = CapabilityRegistry()
    registry.register(_manifest(
        "provider.a", readiness="smoke_tested", permissions=("network.scan",),
        impact="moderate", input_schema={"type": "object"},
        output_schema={"type": "object"},
    ))
    valid = CapabilityRequirements(
        required_permissions=("network.scan",), maximum_impact="moderate",
        required_input_schema={"type": "object"},
        required_output_schema={"type": "object"},
    )
    assert registry.resolve("network.port_scan", valid).manifest.provider_id == "provider.a"
    for bad in (
        CapabilityRequirements(required_permissions=("credentials.read",)),
        CapabilityRequirements(maximum_impact="low"),
        CapabilityRequirements(required_input_schema={"type": "array"}),
        CapabilityRequirements(required_output_schema={"type": "array"}),
        CapabilityRequirements(maximum_timeout_s=301),
    ):
        with pytest.raises(CapabilityUnavailable):
            registry.resolve("network.port_scan", bad)


def test_resolver_rejects_invalid_resource_constraints():
    import math

    import pytest
    registry = CapabilityRegistry()
    registry.register(_manifest("provider.a"))
    for value in (0, -1, math.nan, math.inf, True):
        with pytest.raises(ValueError):
            registry.resolve("network.port_scan", CapabilityRequirements(maximum_timeout_s=value))
    with pytest.raises(ValueError):
        registry.resolve("network.port_scan", CapabilityRequirements(maximum_impact="unbounded"))
    with pytest.raises(TypeError):
        registry.resolve("network.port_scan", CapabilityRequirements(required_input_schema=[]))


def test_resolver_rejects_unsupported_provider_versions():
    import pytest

    registry = CapabilityRegistry()
    registry.register(_manifest("provider.a"))
    with pytest.raises(CapabilityUnavailable, match="version"):
        registry.resolve("network.port_scan", CapabilityRequirements(
            allowed_versions=("2.0.0",),
        ))
    assert registry.resolve("network.port_scan", CapabilityRequirements(
        allowed_versions=("1.0.0",),
    )).manifest.provider_version == "1.0.0"


def test_resolver_enforces_manifest_fingerprint_and_side_effect_allowlist():
    import pytest

    registry = CapabilityRegistry()
    manifest = _manifest(
        "provider.a", permissions=("network.scan",),
        side_effects=("network_traffic", "target_logs"),
    )
    registry.register(manifest)
    for constraints in (
        CapabilityRequirements(allowed_side_effects=()),
        CapabilityRequirements(allowed_side_effects=("network_traffic",)),
        CapabilityRequirements(allowed_fingerprints=("0" * 64,)),
    ):
        with pytest.raises(CapabilityUnavailable):
            registry.resolve("network.port_scan", constraints)
    selected = registry.resolve(
        "network.port_scan",
        CapabilityRequirements(
            allowed_side_effects=("network_traffic", "target_logs"),
            allowed_fingerprints=(manifest.fingerprint,),
        ),
    )
    assert selected.manifest.fingerprint == manifest.fingerprint


def test_manifest_collection_contract_rejects_scalar_strings():
    import pytest

    with pytest.raises(ValueError, match="array"):
        CapabilityManifest(capability_id="test", provider_id="invalid", provider_version="v1", transports=("local_process",), target_types="ip")
    with pytest.raises(ValueError, match="transport"):
        CapabilityManifest(
            capability_id="test", provider_id="invalid", provider_version="v1",
            transports="local_process",
        )
    registry = CapabilityRegistry()
    registry.register(_manifest("provider.a"))
    with pytest.raises(ValueError, match="allowlists"):
        registry.resolve("network.port_scan", CapabilityRequirements(
            allowed_versions="1.0.0",
        ))


def test_registry_digest_changes_only_for_new_persisted_manifests(tmp_path):
    from whaxon.core.store import JobStore

    store = JobStore(tmp_path / "provider-revisions.db")
    registry = CapabilityRegistry(store)
    first = _manifest("provider.one")
    registry.register(first)
    digest = registry.digest
    registry.register(first)
    assert registry.digest == digest
    registry.register(_manifest("provider.two"))
    assert registry.digest != digest
    assert CapabilityRegistry(store).digest == registry.digest



def test_scope_mode_round_trip_and_default_fingerprint_compatibility():
    manifest = _manifest("provider.scope_mode")
    legacy_payload = manifest.to_dict()

    assert "scope_mode" not in legacy_payload
    assert CapabilityManifest.from_dict(legacy_payload).fingerprint == manifest.fingerprint

    for scope_mode in ("dns_query", "pinned_network"):
        explicit = _manifest("provider.scope_mode", scope_mode=scope_mode)
        restored = CapabilityManifest.from_dict(explicit.to_dict())
        assert restored.scope_mode == scope_mode
        assert restored.fingerprint == explicit.fingerprint
        assert explicit.fingerprint != manifest.fingerprint


def test_scope_mode_rejects_unknown_values():
    import pytest

    with pytest.raises(ValueError, match="scope mode"):
        _manifest("provider.invalid_scope_mode", scope_mode="resolve_then_connect")
