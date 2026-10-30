# Cryptographic Handoff: Observation Probe Extension

## Extending the Validator: How AI Self-Heals the Trust Layer

### The limitation

The validator originally replayed payload-shaped findings such as SQL injection and reflected XSS. Environmental observations such as an open TCP port are different: they describe a property of a service at a host and port, not a payload that can be replayed through one HTTP request. The previous behavior correctly left `open_port` findings as `candidate`, but it had no dedicated verification primitive for them.

### The new primitive

The observation-probe layer adds `src/whaxon/core/probes.py` with a deterministic `ProbeRunner`. It supports two narrowly defined observations:

- **TCP reachability:** a successful connection verifies that the selected TCP port accepted a connection.
- **TLS handshake:** for known TLS services and ports, a successful handshake verifies that a TLS endpoint responded.

The runner validates its host, port, and timeout inputs. It uses Python's socket and TLS APIs instead of interpolating finding data into a shell command. That avoids shell injection and keeps the verification path reviewable. It does not run arbitrary commands supplied by a finding.

### Validator integration

`Validator.validate()` now routes `kind="open_port"` to the observation-probe path before HTTP payload replay. The target hostname comes from the caller-supplied target URL; the port and service come from the finding. A finding-supplied host that conflicts with the target URL is rejected as inconclusive, and unsupported protocols remain candidates.

Outcomes preserve the validator's existing three-state contract:

- `verified`: the TCP connection succeeded. When the TLS handshake also succeeds, the reason records that stronger observation; if it fails after TCP acceptance, the reason makes clear that only port reachability was verified.
- `refuted`: the TCP connection was refused.
- `candidate`: the TCP connection timed out or network/DNS conditions were inconclusive. A failed TLS handshake after TCP connection does not refute an `open_port` finding; the port was reachable, though the advertised TLS service may be misidentified.
- `candidate`: the input was incomplete, DNS/network conditions were inconclusive, or the probe timed out.

A successful connection proves reachability only. It does not prove exploitability or that the service is vulnerable. Certificate verification is intentionally not used as a trust judgment in this reachability probe; certificate assessment should be a separate finding type.

### Tests and reproducibility

`tests/test_probes.py` covers a local listening TCP port, invalid input, validator routing for `pentest-ground.com:81`, and an opt-in live integration test. The live check is skipped during ordinary test runs so the unit suite does not depend on a third-party host being available. Run it explicitly with:

```bash
WHAXON_RUN_LIVE_PROBES=1 pytest -q tests/test_probes.py
```

The local tests are deterministic and do not require external network access. The live test verifies the lab's current state at test time; it is not a stable unit-test assertion.

### Trust-layer boundary

This extension closes a validation gap without turning the validator into an unrestricted command executor. Probe definitions remain code-reviewed, bounded, and auditable. A later extension can add new typed observation strategies (for example, HTTP security-header checks) with their own explicit success criteria and tests, rather than accepting arbitrary shell text from findings.
