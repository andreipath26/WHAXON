from whaxon.core.findings import parse_findings


def test_nmap_ports():
    out = parse_findings("nmap", [
        ("stdout", "22/tcp open ssh"),
        ("stdout", "80/tcp open http"),
        ("stdout", "8080/tcp closed x"),
    ])
    assert len(out) == 2
    assert {f.data["port"]: f.severity for f in out}[22] == "medium"

def test_nikto():
    out = parse_findings("nikto", [("stdout", "+ /backup.sql: Database backup file found.")])
    assert out[0].severity == "high"

def test_gobuster_filters_404():
    out = parse_findings("gobuster", [
        ("stdout", "/a (Status: 200) [Size: 1]"),
        ("stdout", "/b (Status: 404) [Size: 0]"),
    ])
    assert len(out) == 1

def test_unknown_tool():
    assert parse_findings("nope", [("stdout", "hi")]) == []


def test_nikto_adapter_parses_plugin_ids_paths_and_see_urls():
    from whaxon.adapters.nikto import NiktoAdapter

    adapter = NiktoAdapter()
    findings = adapter.parse([
        ("stdout", "+ [750001] /actuator/env: Spring Boot Actuator endpoint exposed "
                   "See: https://www.acunetix.com/vulnerabilities/web/spring-boot-actuator/"),
        ("stdout", "+ [750500] /config/: Configuration directory exposed"),
        ("stdout", "+ [013587] /: HTTP methods allow TRACE"),
        ("stdout", "+ [750001] /actuator/env: Spring Boot Actuator endpoint exposed "
                   "See: https://www.acunetix.com/vulnerabilities/web/spring-boot-actuator/"),
        ("stderr", "+ [999999] /ignored: stderr is not a finding"),
        ("stdout", "+ Target IP: 192.0.2.10"),
    ])

    assert len(findings) == 3
    by_id = {finding.data["nikto_id"]: finding for finding in findings}
    assert by_id["750001"].data["path"] == "/actuator/env"
    assert by_id["750001"].data["see"].startswith("https://")
    assert by_id["750001"].severity == "high"
    assert by_id["750500"].data["path"] == "/config/"
    assert by_id["013587"].data["path"] == "/"
