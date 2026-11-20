"""Recon pipeline tests. Focus on the seam — that recon findings actually
reach the correlator and produce correlated findings."""
from __future__ import annotations

from whaxon.core.findings import Finding
from whaxon.core.recon import ReconRunner


def _make_core(tmp_path, monkeypatch):
    """Reuse the project's app factory to get a wired Core, event bus, store."""
    from tests.test_server import _make_app  # same fixture shape used elsewhere
    _app, core = _make_app(tmp_path, monkeypatch)
    return core


def test_recon_out_of_scope_emits_one_finding_and_touches_nothing(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    called = []
    runner.register("dns", lambda t: (called.append(t), [])[1])

    result = runner.run("203.0.113.5")   # TEST-NET-3, not in default scope
    assert result is None
    assert called == []  # check never ran


def test_recon_in_scope_emits_findings_through_pipeline(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    def fake_tech(t):
        return [
            Finding(kind="tech_detected", severity="info", source="recon:tech",
                    data={"product": "apache", "version": "2.4.25"},
                    raw_line=f"Apache/2.4.25 via {t}",
                    lookup_hint="apache 2.4.25"),
            Finding(kind="open_port", severity="info", source="recon:tech",
                    data={"port": 443, "service": "apache", "version": "2.4.25"},
                    raw_line=f"443/tcp open  https   Apache/2.4.25 via {t}"),
        ]
    runner.register("tech", fake_tech)

    job_id = runner.run("127.0.0.1")   # loopback, in default scope
    assert job_id is not None
    assert job_id.startswith("recon:127.0.0.1:")

    raws = core.store.get_findings(job_id)
    assert any(f["kind"] == "tech_detected" for f in raws)

    correlated = [f for f in raws if f["kind"] == "correlated"]
    assert correlated, f"expected correlator to fire, got {raws}"


def test_recon_check_exception_becomes_error_finding(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    def boom(t):
        raise RuntimeError("simulated failure")
    runner.register("dns", boom)

    job_id = runner.run("127.0.0.1")
    raws = core.store.get_findings(job_id)
    assert any(f["kind"] == "recon_error" for f in raws)


def test_recon_robots_emits_disallow_and_sitemap(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_robots
    runner.register("robots", check_robots)


    class _FakeResp:
        def __init__(self, body, url):
            self._body = body.encode("utf-8")
            self._url = url
        def read(self, n=None):
            return self._body[:n] if n else self._body
        def geturl(self):
            return self._url
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith("/robots.txt"):
            return _FakeResp(
                "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
                "Sitemap: https://127.0.0.1/sitemap.xml\n",
                url,
            )
        if url.endswith("/sitemap.xml"):
            return _FakeResp(
                "<?xml version='1.0'?><urlset>"
                "<url><loc>https://127.0.0.1/page1</loc></url>"
                "</urlset>",
                url,
            )
        raise RuntimeError(f"unexpected URL: {url}")

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["robots"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "robots_disallow" in kinds
    assert "robots_sitemap_ref" in kinds
    assert "sitemap_url" in kinds
    disallowed = [f["data"]["path"] for f in raws if f["kind"] == "robots_disallow"]
    assert "/admin" in disallowed and "/backup" in disallowed


def test_recon_security_txt_present(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_security_txt
    runner.register("security_txt", check_security_txt)


    class _FakeResp:
        def __init__(self, body, url):
            self._body = body.encode("utf-8")
            self._url = url
        def read(self, n=None):
            return self._body[:n] if n else self._body
        def geturl(self):
            return self._url
        def __enter__(self): return self
        def __exit__(self, *a): return False

    body = (
        "# Our security policy\n"
        "Contact: mailto:security@example.com\n"
        "Contact: https://example.com/report\n"
        "Expires: 2027-01-01T00:00:00.000Z\n"
        "Preferred-Languages: en, fr\n"
        "Canonical: https://example.com/.well-known/security.txt\n"
    )

    def fake_urlopen(req, timeout=None):
        return _FakeResp(body, req.full_url)

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["security_txt"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "security_txt" in kinds
    contacts = [f["data"]["value"] for f in raws
                if f["kind"] == "security_txt" and f["data"]["field"] == "Contact"]
    assert "mailto:security@example.com" in contacts
    assert "https://example.com/report" in contacts


def test_recon_security_txt_missing(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_security_txt
    runner.register("security_txt", check_security_txt)


    def fake_urlopen(req, timeout=None):
        raise OSError("404 Not Found")

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["security_txt"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "security_txt_missing" in kinds


def test_recon_cookies_flags_missing_attributes(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_cookies
    runner.register("cookies", check_cookies)

    from email.message import Message

    class _FakeHeaders:
        def __init__(self, cookie_values):
            self._m = Message()
            for c in cookie_values:
                self._m["Set-Cookie"] = c
        def get_all(self, name):
            return self._m.get_all(name) or []

    class _FakeResp:
        def __init__(self, cookie_values):
            self.headers = _FakeHeaders(cookie_values)
        def read(self, n=None):
            return b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    cookies = [
        "session=abc123; Path=/",                        # missing Secure, HttpOnly, SameSite
        "theme=dark; Secure; HttpOnly; SameSite=Lax",    # complete
        "tracker=xyz; Secure; SameSite=None",            # missing HttpOnly
    ]

    def fake_urlopen(req, timeout=None):
        return _FakeResp(cookies)

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["cookies"])
    raws = core.store.get_findings(job_id)
    cookie_findings = [f for f in raws if f["kind"] == "cookie_insecure"]
    # session: 3 missing; tracker: 1 missing; theme: 0
    assert len(cookie_findings) == 4
    session_missing = sorted(f["data"]["missing"] for f in cookie_findings
                             if f["data"]["cookie"] == "session")
    assert session_missing == ["httponly", "samesite", "secure"]
    theme_findings = [f for f in cookie_findings if f["data"]["cookie"] == "theme"]
    assert theme_findings == []


def test_recon_redirects_detects_downgrade(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_redirects
    runner.register("redirects", check_redirects)

    import urllib.error as _ue
    import urllib.request as _ur
    from email.message import Message

    # Simulate: https://127.0.0.1/ -> http://127.0.0.1/ -> 200
    def fake_open(opener, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url == "https://127.0.0.1/":
            h = Message()
            h["Location"] = "http://127.0.0.1/"
            raise _ue.HTTPError(url, 301, "Moved", h, None)
        if url == "http://127.0.0.1/":
            class _Ok:
                headers = {}
            return _Ok()
        raise RuntimeError(f"unexpected: {url}")

    monkeypatch.setattr(_ur.OpenerDirector, "open", fake_open)

    job_id = runner.run("127.0.0.1", checks=["redirects"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "redirect_downgrade" in kinds
    downgrade = next(f for f in raws if f["kind"] == "redirect_downgrade")
    assert downgrade["data"]["from"].startswith("https://")
    assert downgrade["data"]["to"].startswith("http://")


def test_recon_redirects_clean_https_chain(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_redirects
    runner.register("redirects", check_redirects)

    import urllib.error as _ue
    import urllib.request as _ur
    from email.message import Message

    # https://127.0.0.1/a -> https://127.0.0.1/b -> 200. No downgrade.
    def fake_open(opener, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url == "https://127.0.0.1/":
            h = Message()
            h["Location"] = "/b"
            raise _ue.HTTPError(url, 301, "Moved", h, None)
        if url == "https://127.0.0.1/b":
            class _Ok:
                headers = {}
            return _Ok()
        raise RuntimeError(f"unexpected: {url}")

    monkeypatch.setattr(_ur.OpenerDirector, "open", fake_open)

    job_id = runner.run("127.0.0.1", checks=["redirects"])
    # Clean HTTPS->HTTPS chain: one hop, no downgrade, no cross-origin,
    # no chain finding. The runner produces no findings, so no job is created.
    assert job_id is None


def test_recon_waf_detects_cloudflare(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_waf
    runner.register("waf", check_waf)

    from email.message import Message

    class _FakeHeaders:
        def __init__(self, headers_map, cookies):
            self._m = Message()
            for k, v in headers_map.items():
                self._m[k] = v
            for c in cookies:
                self._m["Set-Cookie"] = c
        def items(self):
            return [(k, v) for k, v in self._m.items()]
        def get_all(self, name):
            return self._m.get_all(name) or []

    class _FakeResp:
        def __init__(self, headers_map, cookies):
            self.headers = _FakeHeaders(headers_map, cookies)
        def read(self, n=None):
            return b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        return _FakeResp(
            {"Server": "cloudflare", "CF-RAY": "abc123", "CF-Cache-Status": "HIT"},
            ["__cf_bm=xyz; Path=/; Secure"],
        )

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["waf"])
    raws = core.store.get_findings(job_id)
    waf_findings = [f for f in raws if f["kind"] == "waf_detected"]
    assert len(waf_findings) >= 1
    names = [f["data"]["waf"] for f in waf_findings]
    assert "cloudflare" in names


def test_recon_waf_no_match(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_waf
    runner.register("waf", check_waf)

    from email.message import Message

    class _FakeHeaders:
        def __init__(self, headers_map):
            self._m = Message()
            for k, v in headers_map.items():
                self._m[k] = v
        def items(self):
            return list(self._m.items())
        def get_all(self, name):
            return self._m.get_all(name) or []

    class _FakeResp:
        def __init__(self, headers_map):
            self.headers = _FakeHeaders(headers_map)
        def read(self, n=None):
            return b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        return _FakeResp({"Server": "nginx/1.20.1"})

    monkeypatch.setattr("whaxon.core.recon_checks._open_no_redirect", fake_urlopen)

    job_id = runner.run("127.0.0.1", checks=["waf"])
    # No findings -> no job
    assert job_id is None


def test_recon_dns_full_all_present(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_dns_full
    runner.register("dns_full", check_dns_full)

    import dns.exception
    import dns.resolver

    class _RR:
        def __init__(self, text): self._t = text
        def to_text(self): return self._t

    class _Answers:
        def __init__(self, rrs):
            self.rrset = object() if rrs else None
            self._rrs = rrs
        def __iter__(self): return iter(self._rrs)

    def fake_resolve(name, rtype, raise_on_no_answer=False):
        if rtype == "CAA":
            return _Answers([_RR('0 issue "letsencrypt.org"')])
        if rtype == "TXT" and name.startswith("_dmarc."):
            return _Answers([_RR('"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"')])
        if rtype == "TXT":
            return _Answers([_RR('"v=spf1 include:_spf.example.com -all"')])
        raise dns.resolver.NoAnswer

    monkeypatch.setattr(dns.resolver.Resolver, "resolve",
                        lambda self, name, rtype, raise_on_no_answer=False: fake_resolve(name, rtype, raise_on_no_answer))

    job_id = runner.run("127.0.0.1", checks=["dns_full"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "dns_caa" in kinds
    assert "dns_dmarc" in kinds
    assert "dns_spf" in kinds
    assert "dns_dmarc_missing" not in kinds
    assert "dns_spf_missing" not in kinds


def test_recon_dns_full_all_missing(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_dns_full
    runner.register("dns_full", check_dns_full)

    import dns.resolver

    def fake_resolve(self, name, rtype, raise_on_no_answer=False):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)

    job_id = runner.run("127.0.0.1", checks=["dns_full"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "dns_caa_missing" in kinds
    assert "dns_dmarc_missing" in kinds
    assert "dns_spf_missing" in kinds


def test_recon_dns_full_permissive_dmarc(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)

    from whaxon.core.recon_checks import check_dns_full
    runner.register("dns_full", check_dns_full)

    import dns.resolver

    class _RR:
        def __init__(self, text): self._t = text
        def to_text(self): return self._t
    class _Answers:
        def __init__(self, rrs):
            self.rrset = object() if rrs else None
            self._rrs = rrs
        def __iter__(self): return iter(self._rrs)

    def fake_resolve(self, name, rtype, raise_on_no_answer=False):
        if rtype == "CAA":
            return _Answers([])
        if rtype == "TXT" and name.startswith("_dmarc."):
            return _Answers([_RR('"v=DMARC1; p=none"')])
        if rtype == "TXT":
            return _Answers([_RR('"v=spf1 +all"')])
        raise dns.resolver.NoAnswer

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)

    job_id = runner.run("127.0.0.1", checks=["dns_full"])
    raws = core.store.get_findings(job_id)
    kinds = [f["kind"] for f in raws]
    assert "dns_dmarc_permissive" in kinds
    permissive = next(f for f in raws if f["kind"] == "dns_dmarc_permissive")
    assert permissive["severity"] == "medium"
    spf = next((f for f in raws if f["kind"] == "dns_spf"), None)
    assert spf is not None
    assert spf["severity"] == "medium"

def test_recon_redirects_reports_but_does_not_follow_cross_origin(tmp_path, monkeypatch):
    core = _make_core(tmp_path, monkeypatch)
    runner = ReconRunner(core.scope, core.bus, core.runner._resolve_findings)
    from whaxon.core.recon_checks import check_redirects
    runner.register("redirects", check_redirects)

    import urllib.error as _ue
    import urllib.request as _ur
    from email.message import Message

    requested = []

    def fake_open(opener, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        requested.append(url)
        if url == "https://127.0.0.1/":
            headers = Message()
            headers["Location"] = "http://example.com/"
            raise _ue.HTTPError(url, 302, "Found", headers, None)
        raise AssertionError(f"cross-origin redirect must not be requested: {url}")

    monkeypatch.setattr(_ur.OpenerDirector, "open", fake_open)
    job_id = runner.run("127.0.0.1", checks=["redirects"])
    assert requested == ["https://127.0.0.1/"]
    findings = core.store.get_findings(job_id)
    assert any(f["kind"] == "redirect_cross_origin" for f in findings)
