"""Tests for §21.8: _lookup_hint must never fabricate a product."""
from whaxon.adapters.nmap import _extract_product, _lookup_hint


def test_extract_product_werkzeug():
    assert _extract_product("Werkzeug httpd 3.1.8") == "werkzeug"


def test_extract_product_nginx():
    assert _extract_product("nginx 1.18.0") == "nginx"


def test_extract_product_apache_httpd_longest_wins():
    # "apache httpd" must win over bare "apache"
    assert _extract_product("Apache httpd 2.4.7 (Ubuntu)") == "apache httpd"


def test_extract_product_openssh():
    assert _extract_product("OpenSSH 8.2p1 Ubuntu 4ubuntu0.5") == "openssh"


def test_extract_product_vsftpd():
    assert _extract_product("vsftpd 3.0.3") == "vsftpd"


def test_extract_product_tomcat():
    assert _extract_product("Apache Tomcat 9.0.45") == "apache tomcat"


def test_extract_product_jetty():
    assert _extract_product("Jetty 9.4.43.v20210629") == "jetty"


def test_extract_product_gunicorn():
    assert _extract_product("gunicorn 20.1.0") == "gunicorn"


def test_extract_product_uvicorn():
    assert _extract_product("uvicorn 0.15.0") == "uvicorn"


def test_extract_product_bare_version_returns_empty():
    assert _extract_product("2.4.7") == ""


def test_lookup_hint_werkzeug_does_not_fabricate_apache():
    # The bug §21.8 named: service "http" + version naming Werkzeug
    # must NOT produce "apache 3.1.8".
    hint = _lookup_hint("http", "Werkzeug httpd 3.1.8")
    assert hint == "werkzeug 3.1.8"
    assert "apache" not in hint


def test_lookup_hint_http_with_bare_version_returns_empty():
    # service "http" is a protocol label, not a product. Bare version
    # cannot be resolved to a product. Empty is correct.
    assert _lookup_hint("http", "2.4.7") == ""


def test_lookup_hint_nginx_bare_version_falls_back_to_service():
    # "nginx" IS a product name, so fallback is honest.
    assert _lookup_hint("nginx", "1.18.0") == "nginx 1.18.0"


def test_lookup_hint_openssh_named_in_version():
    # _NMAP_VERSION_NUM_RE captures the numeric version (8.2), not the
    # distro suffix (p1). That is pre-existing behavior, unchanged here.
    hint = _lookup_hint("ssh", "OpenSSH 8.2p1")
    assert hint == "openssh 8.2"


def test_lookup_hint_unknown_service_returns_empty():
    assert _lookup_hint("unknown_svc", "1.0") == ""


def test_lookup_hint_empty_version_returns_empty():
    assert _lookup_hint("http", "") == ""
