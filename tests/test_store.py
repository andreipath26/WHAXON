import threading
import time
import pytest
from whaxon.core.store import JobStore

@pytest.fixture
def store(tmp_path):
    return JobStore(tmp_path / "test.db")

def test_create_and_get(store):
    store.create("abc")
    assert store.get("abc")["status"] == "starting"

def test_full_lifecycle(store):
    store.create("j1")
    store.set_started("j1", "nmap", "127.0.0.1")
    store.append_line("j1", "stdout", "a")
    store.append_line("j1", "stderr", "b")
    store.set_finished("j1", 0, 1.5)
    j = store.get("j1")
    assert j["status"] == "finished"
    assert len(j["lines"]) == 2

def test_findings_roundtrip(store):
    store.create("f1")
    store.append_finding("f1", {"kind": "open_port", "severity": "high", "source": "nmap",
                                "data": {"port": 22}, "raw_line": "22/tcp"}, 0)
    out = store.get_findings("f1")
    assert out[0]["severity"] == "high"
    assert out[0]["data"]["port"] == 22

def test_history_ordering(store):
    for i in range(3):
        store.create(f"h{i}")
        store.set_finished(f"h{i}", 0, 0.1)
        time.sleep(0.01)
    assert store.history()[0]["id"] == "h2"

def test_evidence_crud(store):
    store.create("e1")
    seq = store.add_evidence("e1", "note", "n", note="hi")
    store.add_evidence("e1", "file", "s.png", path="evidence/e1/s.png")
    assert len(store.list_evidence("e1")) == 2
    assert store.remove_evidence("e1", seq) is True

def test_concurrent_writes(store):
    def worker(jid):
        store.create(jid)
        for i in range(50):
            store.append_line(jid, "stdout", f"l{i}")
        store.set_finished(jid, 0, 1.0)
    ts = [threading.Thread(target=worker, args=(f"c{i}",)) for i in range(4)]
    for t in ts: t.start()
    for t in ts: t.join()
    for i in range(4):
        assert len(store.get(f"c{i}")["lines"]) == 50
