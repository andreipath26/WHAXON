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
