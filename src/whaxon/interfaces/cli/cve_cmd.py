"""whaxon cve — NVD CVE lookup with a local SQLite cache.

Reads from data/cve_cache.db first. On cache miss, queries the NVD
v2.0 API (services.nvd.nist.gov/rest/json/cves/2.0) and stores the
result. Cache entries record their fetch time; entries older than
CACHE_TTL_DAYS are refetched.

Rate limits: NVD allows ~5 unauthenticated requests per 30s. If
NVD_API_KEY is set in the environment, the limit rises to ~50 per 30s.
On HTTP 403/429, we surface a clear message and exit 2.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


EXIT_OK = 0
EXIT_NO_RESULTS = 2
EXIT_RATE_LIMITED = 3
EXIT_NETWORK = 4
EXIT_USAGE = 64

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_DAYS = 7
USER_AGENT = "whaxon/0.3"
DEFAULT_CACHE = Path("data") / "cve_cache.db"


def _usage() -> None:
    print("Usage:")
    print("  whaxon cve CVE-2021-44228          # exact CVE lookup")
    print("  whaxon cve --keyword \"apache 2.4.7\"  # keyword search")
    print()
    print("Options:")
    print("  --json          emit JSON instead of a table")
    print("  --limit N       max results (keyword mode; default 10)")
    print("  --no-cache      bypass the local cache, always hit NVD")
    print("  --refresh       refetch even if cached")
    print("  --data DIR      data directory (default ./data)")


def _cache_conn(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(path))
    c.execute(
        "CREATE TABLE IF NOT EXISTS cve_cache ("
        "key TEXT PRIMARY KEY, payload TEXT NOT NULL, fetched_at REAL NOT NULL"
        ")"
    )
    c.commit()
    return c


def _cache_get(conn: sqlite3.Connection, key: str, ttl_days: int):
    row = conn.execute(
        "SELECT payload, fetched_at FROM cve_cache WHERE key=?", (key,)
    ).fetchone()
    if row is None:
        return None
    payload, fetched_at = row
    age = time.time() - fetched_at
    if age > ttl_days * 86400:
        return None
    return json.loads(payload)


def _cache_put(conn: sqlite3.Connection, key: str, payload: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO cve_cache (key, payload, fetched_at) VALUES (?, ?, ?)",
        (key, json.dumps(payload), time.time()),
    )
    conn.commit()


def _fetch(url: str) -> tuple[bool, dict | str, int]:
    """Returns (ok, data_or_error, http_status)."""
    headers = {"User-Agent": USER_AGENT}
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key:
        headers["apiKey"] = key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return True, json.loads(r.read().decode("utf-8")), r.status
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            return False, "rate limited by NVD (HTTP %d). Wait ~30s and retry, or set NVD_API_KEY for a higher limit." % e.code, e.code
        return False, f"NVD HTTP {e.code}: {e.reason}", e.code
    except urllib.error.URLError as e:
        return False, f"network error: {e.reason}", 0
    except Exception as e:
        return False, f"{type(e).__name__}: {e}", 0


def _english_description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _cvss_from_metrics(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Return (score, severity, vector) preferring v3.1 > v3.0 > v2."""
    if not metrics:
        return None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if not arr:
            continue
        entry = arr[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        vector = data.get("vectorString")
        if score is not None:
            return float(score), severity, vector
    return None, None, None


def _cwes(cve: dict) -> list[str]:
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                out.append(v)
    # Dedupe, preserving order
    seen = set()
    uniq = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _references(cve: dict, limit: int = 5) -> list[str]:
    urls = []
    for r in cve.get("references") or []:
        u = r.get("url")
        if u:
            urls.append(u)
        if len(urls) >= limit:
            break
    return urls


def _show_one(cve: dict) -> None:
    cid = cve.get("id", "?")
    print(f"  {cid}")
    print(f"  Published: {cve.get('published', '')}")
    print(f"  Modified:  {cve.get('lastModified', '')}")
    print(f"  Status:    {cve.get('vulnStatus', '')}")

    score, sev, vec = _cvss_from_metrics(cve.get("metrics") or {})
    if score is not None:
        line = f"  CVSS:      {score}"
        if sev:
            line += f" ({sev})"
        if vec:
            line += f"  {vec}"
        print(line)

    cwes = _cwes(cve)
    if cwes:
        print(f"  CWE:       {', '.join(cwes)}")

    desc = _english_description(cve)
    if desc:
        print()
        # wrap at ~72 chars
        words = desc.split()
        line = "  "
        for w in words:
            if len(line) + len(w) + 1 > 76:
                print(line)
                line = "  " + w
            else:
                line = line + " " + w if line.strip() else "  " + w
        if line.strip():
            print(line)

    refs = _references(cve)
    if refs:
        print()
        print("  References:")
        for u in refs:
            print(f"    - {u}")


def _show_search_row(cve: dict) -> None:
    cid = cve.get("id", "?")
    score, sev, _ = _cvss_from_metrics(cve.get("metrics") or {})
    sev_s = f"{sev:<8s}" if sev else "        "
    score_s = f"{score:>4}" if score is not None else "    "
    desc = _english_description(cve).replace("\n", " ")[:80]
    print(f"  {cid:<18s}  {score_s}  {sev_s}  {desc}")


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        _usage()
        return

    cve_id: str | None = None
    keyword: str | None = None
    as_json = False
    limit = 10
    no_cache = False
    refresh = False
    data_dir = Path("data")

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--json":
            as_json = True; i += 1
        elif a == "--no-cache":
            no_cache = True; i += 1
        elif a == "--refresh":
            refresh = True; i += 1
        elif a == "--keyword" and i + 1 < len(args):
            keyword = args[i + 1]; i += 2
        elif a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                print(f"error: --limit expects an integer, got {args[i+1]!r}", file=sys.stderr)
                sys.exit(EXIT_USAGE)
            i += 2
        elif a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a.startswith("--"):
            print(f"Unknown arg: {a}", file=sys.stderr)
            sys.exit(EXIT_USAGE)
        else:
            if cve_id is not None:
                print(f"error: unexpected extra argument {a!r}", file=sys.stderr)
                sys.exit(EXIT_USAGE)
            cve_id = a
            i += 1

    if cve_id is None and keyword is None:
        print("error: whaxon cve requires a CVE id or --keyword", file=sys.stderr)
        _usage()
        sys.exit(EXIT_USAGE)

    # ---- Exact ID mode ----
    if cve_id is not None:
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            print(f"error: not a CVE id: {cve_id!r}", file=sys.stderr)
            sys.exit(EXIT_USAGE)

        cache_path = data_dir / "cve_cache.db"
        cache_key = f"id:{cve_id}"
        payload = None
        if not no_cache and not refresh:
            conn = _cache_conn(cache_path)
            try:
                payload = _cache_get(conn, cache_key, CACHE_TTL_DAYS)
            finally:
                conn.close()

        if payload is None:
            url = f"{NVD_BASE}?cveId={urllib.parse.quote(cve_id)}"
            ok, data, status = _fetch(url)
            if not ok:
                print(f"error: {data}", file=sys.stderr)
                sys.exit(EXIT_RATE_LIMITED if status in (403, 429) else EXIT_NETWORK)
            payload = data
            conn = _cache_conn(cache_path)
            try:
                _cache_put(conn, cache_key, payload)
            finally:
                conn.close()

        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            print(f"No NVD record for {cve_id}", file=sys.stderr)
            sys.exit(EXIT_NO_RESULTS)

        cve = vulns[0]["cve"]
        if as_json:
            print(json.dumps(cve, indent=2))
        else:
            _show_one(cve)
        return

    # ---- Keyword mode ----
    url = (
        f"{NVD_BASE}?keywordSearch={urllib.parse.quote(keyword)}"
        f"&resultsPerPage={limit}"
    )
    ok, data, status = _fetch(url)
    if not ok:
        print(f"error: {data}", file=sys.stderr)
        sys.exit(EXIT_RATE_LIMITED if status in (403, 429) else EXIT_NETWORK)

    vulns = data.get("vulnerabilities") or []
    if as_json:
        print(json.dumps(data, indent=2))
        return

    print(f"Keyword: {keyword}")
    print(f"Total:   {data.get('totalResults', 0)}")
    print()
    for v in vulns[:limit]:
        _show_search_row(v["cve"])
    if not vulns:
        print("  (no results)")


if __name__ == "__main__":
    main()