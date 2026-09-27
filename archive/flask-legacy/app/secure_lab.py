#!/usr/bin/env python3
"""Secure Lab: local defensive toolkit with authenticated SSH command runner."""
from __future__ import annotations
import ast, csv, hashlib, ipaddress, json, os, re, secrets, socket, subprocess, uuid, ssl, urllib.request, urllib.error, sys, shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, render_template_string, redirect, url_for, flash
from catalog_manager import install_catalog, fetch_update_manifest, update_catalog_from_manifest
from tool_catalog import load as load_tool_registry

ROOT=Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
DATA=ROOT/"secure_lab_data"; AUDIT=DATA/"ssh_cleanup_audit.jsonl"; TELNET_AUDIT=DATA/"telnet_cleanup_audit.jsonl"; WEB_AUDIT=DATA/"http_audit.jsonl"
REMOTE_LOG_DIR="/tmp/secure-lab-session-logs"
app=Flask(__name__); app.secret_key=os.environ.get("SECURE_LAB_SECRET",secrets.token_hex(32)); app.config["MAX_CONTENT_LENGTH"]=110*1024*1024

PAGE=r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Lab</title><style>
:root{color-scheme:dark;--bg:#0d121a;--panel:#151e2b;--line:#2c3a4d;--fg:#e8eef7;--muted:#a6b4c8;--accent:#7dc0ff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui}header{padding:24px max(18px,calc((100% - 1200px)/2));background:#111925;border-bottom:1px solid var(--line)}h1{margin:0;font-size:25px}header p,.hint,footer{color:var(--muted)}main{max-width:1200px;margin:22px auto;padding:0 18px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}.tabs a{color:var(--fg);text-decoration:none;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:9px 13px}.tabs a.active{background:var(--accent);color:#06111d;border-color:var(--accent);font-weight:700}.grid{display:grid;grid-template-columns:1fr;gap:16px;align-items:start}.grid>.card{display:none}.grid>.card.active{display:block}.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:18px;min-width:0}h2{font-size:18px;margin:0 0 8px}.hint{font-size:13px;margin:0 0 12px}label{display:block;color:var(--muted);font-size:13px;margin:10px 0 5px}input,textarea,select,button{font:inherit}input,textarea,select{width:100%;background:#0d141e;border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:10px}textarea{min-height:105px}button{background:var(--accent);color:#06111d;font-weight:bold;border:0;border-radius:8px;padding:10px 14px;margin-top:11px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a0f16;border:1px solid var(--line);padding:13px;border-radius:8px;max-height:450px;overflow:auto}.notice{padding:11px;background:#193a2c;border:1px solid #326348;border-radius:9px;margin-bottom:12px}footer{font-size:12px;margin:24px 0}</style></head><body><header><h1>Secure Lab</h1><p>Exploit-DB · SSH/Telnet · HTTP/HTTPS · local Nmap/SQLmap</p></header><main>
{% for m in get_flashed_messages() %}<div class="notice">{{m}}</div>{% endfor %}<nav class="tabs" aria-label="Tools">{% for id,name in tabs %}<a href="{{ url_for('tool_page', tool_id=id) }}" class="{% if active == id %}active{% endif %}" {% if active == id %}aria-current="page"{% endif %}>{{name}}</a>{% endfor %}</nav><div class="grid">
<section class="card {% if active == 'exploitdb' %}active{% endif %}" id="exploitdb"><h2>Exploit-DB</h2><p class="hint">Metadata-only search in /usr/share/exploitdb/files_exploits.csv.</p><form action="/exploit" method="post"><label>Terms</label><input name="terms" required><label>Match</label><select name="mode"><option value="all">All terms</option><option value="any">Any term</option><option value="phrase">Phrase</option></select><button>Search</button></form>{% if out and out.kind=="exploit" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'catalog' %}active{% endif %}" id="catalog"><h2>Catalog & updates</h2><p class="hint">Import an Exploit-DB CSV/ZIP without internet. Online update checks require SECURE_LAB_UPDATE_MANIFEST_URL to point to a trusted HTTPS JSON manifest.</p><form action="/catalog/import" method="post" enctype="multipart/form-data"><label>Local catalog CSV or ZIP</label><input type="file" name="catalog_file" accept=".csv,.zip" required><button>Refresh offline catalog</button></form><form action="/updates/check" method="post"><button>Check for updates</button></form><form action="/updates/catalog" method="post"><button>Download & install catalog update</button></form>{% if out and out.kind=="updates" %}<pre>{{out.text}}</pre>{% endif %}</section><section class="card {% if active == 'ssh' %}active{% endif %}" id="ssh"><h2>Remote Terminal (SSH)</h2><p class="hint">Requires Paramiko. Uses known-host verification; unknown host keys are rejected. A unique remote temp log is removed at end; local cleanup audit is retained.</p><form action="/ssh" method="post"><label>Host</label><input name="host" required><label>Port</label><input name="port" type="number" min="1" max="65535" value="22"><label>Username</label><input name="username" required><label>Password (optional; SSH agent/key also supported)</label><input type="password" name="password"><label>Command</label><textarea name="command" required></textarea><button>Connect and execute</button></form>{% if out and out.kind=="ssh" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'telnet' %}active{% endif %}" id="telnet"><h2>Remote Terminal (Telnet)</h2><p class="hint">Telnet is unencrypted and has no SSH-style host-key verification. Use only on trusted networks. Creates a unique temporary remote marker in /tmp/secure-lab-session-logs, removes only that exact marker, and keeps a local cleanup audit. Remote cleanup requires a POSIX shell and write permission.</p><form action="/telnet" method="post"><label>Host</label><input name="host" required><label>Port</label><input name="port" type="number" min="1" max="65535" value="23"><label>Username (optional)</label><input name="username"><label>Password (optional)</label><input type="password" name="password"><label>Command (optional)</label><textarea name="command" placeholder="help"></textarea><button>Connect</button></form>{% if out and out.kind=="telnet" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'web' %}active{% endif %}" id="web"><h2>HTTP / HTTPS</h2><p class="hint">Make a verified HTTP(S) request, inspect status/headers and a capped response body. Redirects are not followed automatically. Public hosts only; no credentials are stored in the audit.</p><form action="/web" method="post"><label>URL</label><input name="url" type="url" placeholder="https://www.google.com/" required><label>Method</label><select name="method"><option>GET</option><option>HEAD</option></select><label>Optional request body (GET only; leave blank normally)</label><textarea name="body" placeholder=""></textarea><button>Send request</button></form>{% if out and out.kind=="web" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'nmap' %}active{% endif %}" id="nmap"><h2>Nmap · loopback only</h2><form action="/nmap" method="post"><label>Target (localhost/loopback only)</label><input name="target" value="127.0.0.1" required><label>Profile</label><select name="profile"><option value="basic">Top 100 TCP ports</option><option value="ports">Selected ports</option></select><label>Ports</label><input name="ports" placeholder="22,80,443 or 1-1024"><button>Run Nmap</button></form>{% if out and out.kind=="nmap" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'sqlmap' %}active{% endif %}" id="sqlmap"><h2>SQLmap · local URL only</h2><p class="hint">Basic GET parameter check only; no shell/takeover/dump options.</p><form action="/sqlmap" method="post"><label>Local HTTP(S) URL</label><input name="url" placeholder="http://127.0.0.1:8080/item?id=1" required><label>Parameter (optional)</label><input name="param"><button>Run check</button></form>{% if out and out.kind=="sqlmap" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'theharvester' %}active{% endif %}" id="theharvester"><h2>theHarvester · domain OSINT</h2><p class="hint">Collects publicly available domain-related information from the selected source. Use only domains you are authorized to assess.</p><form action="/osint/theharvester" method="post"><label>Domain</label><input name="domain" placeholder="example.org" required><label>Source</label><select name="source"><option value="crtsh">crt.sh</option><option value="duckduckgo">duckduckgo</option><option value="bing">bing</option><option value="baidu">baidu</option></select><button>Run lookup</button></form>{% if out and out.kind=="theharvester" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'sherlock' %}active{% endif %}" id="sherlock"><h2>Sherlock · username lookup</h2><p class="hint">Checks public websites for a username. A match is not proof that profiles belong to the same person.</p><form action="/osint/sherlock" method="post"><label>Username</label><input name="username" pattern="[A-Za-z0-9_.-]{1,64}" required><button>Search public sites</button></form>{% if out and out.kind=="sherlock" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'dnsrecon' %}active{% endif %}" id="dnsrecon"><h2>DNSrecon · DNS records</h2><p class="hint">Query common DNS records for a domain. Only query domains within your authorized scope.</p><form action="/osint/dnsrecon" method="post"><label>Domain</label><input name="domain" placeholder="example.org" required><button>Run DNS lookup</button></form>{% if out and out.kind=="dnsrecon" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'exiftool' %}active{% endif %}" id="exiftool"><h2>ExifTool · file metadata</h2><p class="hint">Read metadata from a file you provide. Files are processed in a temporary folder and removed after processing.</p><form action="/osint/exiftool" method="post" enctype="multipart/form-data"><label>Choose a local file</label><input type="file" name="metadata_file" required><button>Inspect metadata</button></form>{% if out and out.kind=="exiftool" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'spiderfoot' %}active{% endif %}" id="spiderfoot"><h2>SpiderFoot · OSINT automation</h2><p class="hint">SpiderFoot has its own web interface and scan lifecycle; this dashboard does not start a scan automatically. Install SpiderFoot separately, then launch it using its official instructions. This panel checks whether its command is available.</p><form action="/osint/spiderfoot" method="post"><button>Check installation</button></form>{% if out and out.kind=="spiderfoot" %}<pre>{{out.text}}</pre>{% endif %}</section>
<section class="card {% if active == 'toolcatalog' %}active{% endif %}" id="toolcatalog"><h2>Tool Integration Catalog</h2><p class="hint">Candidate registry for optional integrations. Kali package and upstream maintenance statuses remain Unverified until checked against authoritative sources. Kali's official package tracker is at <a href="https://pkg.kali.org/" target="_blank" rel="noopener">pkg.kali.org</a>.</p><form method="get" action="/tools-catalog"><label>Filter by name or category</label><input name="q" value="{{ tool_query or '' }}" placeholder="Search candidates"><button>Search catalog</button></form><p class="hint">{{ tool_count }} candidate(s) shown. Package mappings are intentionally blank until verified; no installation is triggered from this page.</p><div style="overflow:auto"><table style="width:100%;border-collapse:collapse"><thead><tr><th align="left">Tool</th><th align="left">Category</th><th align="left">Kali package</th><th align="left">Maintenance</th><th align="left">Install route</th></tr></thead><tbody>{% for t in tool_rows %}<tr style="border-top:1px solid var(--line)"><td style="padding:8px">{{t.name}}</td><td style="padding:8px">{{t.category}}</td><td style="padding:8px">{{t.kali_status}}</td><td style="padding:8px">{{t.maintenance}}</td><td style="padding:8px">{{t.install_method}}</td></tr>{% endfor %}</tbody></table></div><p class="hint">To enable one-click APT installation, first populate that entry's apt_package with a verified exact Kali package name in the registry, then implement an explicit consented install flow. For upstream-only projects, use a pinned release/commit and isolated environment. Do not add third-party apt repositories to Kali's system sources.</p></section><section class="card {% if active == 'variant' %}active{% endif %}" id="variant"><h2>Formatting variant</h2><p class="hint">AST formatting only; code is not executed.</p><form action="/variant" method="post"><label>Python source</label><textarea name="source" required></textarea><button>Create variant</button></form>{% if out and out.kind=="variant" %}<pre>{{out.text}}</pre>{% endif %}</section>
</div><footer>Local UI binds to 127.0.0.1:5001. Do not expose it to untrusted networks. SSH commands run with the remote account's permissions.</footer></main></body></html>'''
TABS=[("toolcatalog","Tool Catalog"),("exploitdb","Exploit-DB"),("catalog","Catalog & updates"),("ssh","SSH"),("telnet","Telnet"),("web","HTTP/HTTPS"),("nmap","Nmap"),("sqlmap","SQLmap"),("theharvester","theHarvester"),("sherlock","Sherlock"),("dnsrecon","DNSrecon"),("exiftool","ExifTool"),("spiderfoot","SpiderFoot"),("variant","Variant")]
def page(out=None, active=None, tool_query=""):
 if active is None:
  active = {"exploit":"exploitdb", "updates":"catalog", "ssh":"ssh", "telnet":"telnet", "web":"web", "nmap":"nmap", "sqlmap":"sqlmap", "theharvester":"theharvester", "sherlock":"sherlock", "dnsrecon":"dnsrecon", "exiftool":"exiftool", "spiderfoot":"spiderfoot", "variant":"variant"}.get(out.get("kind") if out else None, "exploitdb")
 try:
  registry=load_tool_registry(ROOT/"data"/"tool_registry.json")
  q=(tool_query or "").strip().lower()
  tool_rows=[t for t in registry if q in t.get("name","").lower() or q in t.get("category","").lower()]
 except Exception:
  tool_rows=[]
 return render_template_string(PAGE,out=out,tabs=TABS,active=active,tool_rows=tool_rows,tool_count=len(tool_rows),tool_query=tool_query)
def safe_path(raw):
 p=(ROOT/(raw or "")).resolve()
 if not p.is_relative_to(ROOT) or not p.is_file(): raise ValueError("Choose an existing file inside the app folder.")
 return p
def tool_path(name):
 candidates=[ROOT/"tools"/name, ROOT/"tools"/(name+".exe")]
 for candidate in candidates:
  if candidate.is_file(): return str(candidate)
 found=shutil.which(name)
 if found: return found
 raise RuntimeError(f"Missing tool: {name}. Add it under the project tools/ folder or install it on PATH.")
def local(args,timeout=120):
 args=list(args)
 if args and args[0] in ("nmap","sqlmap"): args[0]=tool_path(args[0])
 try: p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
 except FileNotFoundError: raise RuntimeError(f"Missing executable: {args[0]}")
 except subprocess.TimeoutExpired: raise RuntimeError("Command timed out.")
 s=(p.stdout or "")+("\n"+p.stderr if p.stderr else "")
 return (s.strip() or "(No output)")[:200000]+(f"\nExit code: {p.returncode}" if p.returncode else "")
def loopback(host):
 if host.lower().rstrip(".") in ("localhost","localhost.localdomain"): return True
 try: return ipaddress.ip_address(host).is_loopback
 except ValueError: return False
def audit(entry):
 DATA.mkdir(parents=True,exist_ok=True); entry["timestamp_utc"]=datetime.now(timezone.utc).isoformat()
 with AUDIT.open("a",encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
 try: AUDIT.chmod(0o600)
 except OSError: pass

@app.get("/")
def index(): return page()

@app.get("/tools-catalog")
def tools_catalog():
 return page(active="toolcatalog", tool_query=request.args.get("q", ""))

@app.get("/tool/<tool_id>")
def tool_page(tool_id):
 if tool_id not in {item[0] for item in TABS}:
  return "Tool not found", 404
 return page(active=tool_id)
@app.post("/exploit")
def exploit():
 try:
  terms=request.form.get("terms","").lower().split(); path=next((x for x in (DATA/"catalog"/"files_exploits.csv", ROOT/"data"/"files_exploits.csv", ROOT/"tools"/"files_exploits.csv", Path("/usr/share/exploitdb/files_exploits.csv")) if x.is_file()), Path("/usr/share/exploitdb/files_exploits.csv"))
  if not terms: raise ValueError("Enter search terms.")
  if not path.is_file(): raise FileNotFoundError("Exploit-DB CSV not found; install the exploitdb package.")
  rows=[]
  with path.open(encoding="utf-8",errors="replace",newline="") as f:
   for r in csv.DictReader(f):
    s=" ".join(str(v or "") for v in r.values()).lower(); mode=request.form.get("mode","all")
    if (" ".join(terms) in s if mode=="phrase" else any(t in s for t in terms) if mode=="any" else all(t in s for t in terms)): rows.append(r)
  lines=[f"EDB-{r.get('id','')} | {r.get('type','')} | {r.get('platform','')}\n{r.get('description','')}\nhttps://www.exploit-db.com/exploits/{r.get('id','')}" for r in rows[:100]]
  return page({"kind":"exploit","text":f"{len(rows)} result(s) (showing up to 100)\n\n"+"\n\n".join(lines)})
 except Exception as e: flash(str(e)); return redirect(url_for("index"))
@app.post("/catalog/import")
def catalog_import():
 try:
  uploaded=request.files.get("catalog_file")
  if not uploaded or not uploaded.filename: raise ValueError("Choose a local CSV or ZIP file.")
  suffix=Path(uploaded.filename).suffix.lower()
  if suffix not in (".csv", ".zip"): raise ValueError("Only CSV and ZIP imports are supported.")
  import tempfile
  with tempfile.TemporaryDirectory(prefix="securelab-upload-") as td:
   staged=Path(td)/("upload"+suffix); uploaded.save(staged)
   meta=install_catalog(staged, DATA/"catalog")
  flash(f"Offline catalog refreshed: {meta['records']} records; SHA-256 {meta['sha256'][:16]}…")
 except Exception as e: flash(f"Catalog refresh failed: {e}")
 return redirect(url_for("index")+"#catalog")

@app.post("/updates/check")
def updates_check():
 try:
  manifest_url=os.environ.get("SECURE_LAB_UPDATE_MANIFEST_URL", "").strip()
  if not manifest_url: raise ValueError("Set SECURE_LAB_UPDATE_MANIFEST_URL to your trusted HTTPS update-manifest URL first.")
  manifest=fetch_update_manifest(manifest_url)
  lines=[f"Latest version: {manifest.get('latest_version')}"]
  if manifest.get("release_url"): lines.append(f"Release page: {manifest['release_url']}")
  if manifest.get("catalog_version"): lines.append(f"Catalog version: {manifest['catalog_version']}")
  if manifest.get("catalog_url"):
   if request.form.get("refresh_catalog")=="yes":
    meta=update_catalog_from_manifest(manifest, DATA/"catalog")
    lines.append(f"Catalog installed: {meta['records']} rows; SHA-256 {meta['sha256']}")
   else:
    lines.append("Catalog update available. Use the offline import workflow or configure an explicit catalog update action.")
  return page({"kind":"updates","text":"\n".join(lines)})
 except Exception as e: return page({"kind":"updates","text":f"Update check failed: {e}"})

@app.post("/updates/catalog")
def updates_catalog():
 try:
  manifest_url=os.environ.get("SECURE_LAB_UPDATE_MANIFEST_URL", "").strip()
  if not manifest_url: raise ValueError("Set SECURE_LAB_UPDATE_MANIFEST_URL to your trusted HTTPS update-manifest URL first.")
  manifest=fetch_update_manifest(manifest_url)
  meta=update_catalog_from_manifest(manifest, DATA/"catalog")
  return page({"kind":"updates","text":f"Catalog update installed: {meta['records']} records\nSHA-256: {meta['sha256']}\nUpdated: {meta['updated_utc']}"})
 except Exception as e: return page({"kind":"updates","text":f"Catalog update failed: {e}"})

@app.post("/ssh")
def ssh():
 host=request.form.get("host","").strip(); user=request.form.get("username","").strip(); cmd=request.form.get("command",""); sid=uuid.uuid4().hex; log=f"{REMOTE_LOG_DIR}/{sid}.log"; port=int(request.form.get("port",22)); status="not-created"; output=""
 try:
  if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}",host): raise ValueError("Invalid host format.")
  if not user or not cmd.strip() or len(cmd)>8000: raise ValueError("Username and command are required; command limit is 8,000 chars.")
  if not 1<=port<=65535: raise ValueError("Invalid port.")
  import paramiko
  c=paramiko.SSHClient(); c.load_system_host_keys(); c.set_missing_host_key_policy(paramiko.RejectPolicy()); sftp=None
  try:
   c.connect(hostname=host,port=port,username=user,password=request.form.get("password") or None,timeout=12,auth_timeout=15,banner_timeout=12,allow_agent=True,look_for_keys=True)
   sftp=c.open_sftp()
   try: sftp.stat(REMOTE_LOG_DIR)
   except OSError:
    try: sftp.mkdir(REMOTE_LOG_DIR,mode=0o700)
    except OSError: sftp.stat(REMOTE_LOG_DIR)
   with sftp.open(log,"x") as f: f.write(f"session={sid}\nhost={host}\n")
   stdin,stdout,stderr=c.exec_command(cmd,timeout=45); stdin.close()
   o=stdout.read(200001).decode("utf-8","replace"); e=stderr.read(200001).decode("utf-8","replace")
   output=(o+("\n[stderr]\n"+e if e else "")).strip()[:200000] or "(No output)"
  finally:
   if sftp:
    try: sftp.remove(log); status="removed"
    except FileNotFoundError: status="already-absent"
    except Exception as ex: status="failed:"+type(ex).__name__
    sftp.close()
   c.close()
 except Exception as e: output=f"SSH error: {e}"
 finally:
  audit({"session_id":sid,"host":host,"port":port,"username":user,"command_sha256":hashlib.sha256(cmd.encode()).hexdigest(),"remote_log_path":log,"cleanup":status})
 return page({"kind":"ssh","text":f"Session {sid}\nRemote log cleanup: {status}\n\n{output}"})
@app.post("/web")
def web_request():
 u=request.form.get("url","").strip(); method=request.form.get("method","GET").upper(); body=request.form.get("body","")
 status="error"; text_out=""
 try:
  p=urlparse(u)
  if p.scheme not in ("http","https") or not p.hostname or p.username or p.password: raise ValueError("Enter a valid HTTP(S) URL without embedded credentials.")
  if method not in ("GET","HEAD"): raise ValueError("Only GET and HEAD are supported.")
  if body: raise ValueError("Request body is not supported; leave it blank.")
  if len(u)>2048: raise ValueError("URL is too long.")
  # Prevent requests to loopback/private/reserved addresses, including DNS names resolving there.
  infos=socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=="https" else 80),type=socket.SOCK_STREAM)
  ips={ipaddress.ip_address(x[4][0].split("%",1)[0]) for x in infos}
  if not ips or any(not ip.is_global for ip in ips): raise ValueError("Only public, globally routable host addresses are allowed.")
  req=urllib.request.Request(u,method=method,headers={"User-Agent":"SecureLab-HTTP/1.0","Accept":"*/*"})
  class NoRedirect(urllib.request.HTTPRedirectHandler):
   def redirect_request(self, req, fp, code, msg, headers, newurl): return None
  opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
  try: resp=opener.open(req,timeout=12)
  except urllib.error.HTTPError as e: resp=e
  with resp:
   status=resp.status
   headers="\n".join(f"{k}: {v}" for k,v in resp.headers.items())
   raw=b"" if method=="HEAD" else resp.read(65537)
   truncated=len(raw)>65536; raw=raw[:65536]
   body_text=raw.decode(resp.headers.get_content_charset() or "utf-8","replace")
   text_out=f"URL: {u}\nStatus: {status} {resp.reason}\n\nHeaders:\n{headers}\n\nBody (up to 64 KiB):\n{body_text}"+("\n[Body truncated]" if truncated else "")
 except Exception as e: text_out=f"HTTP(S) error: {e}"
 finally:
  try:
   DATA.mkdir(parents=True,exist_ok=True)
   with WEB_AUDIT.open("a",encoding="utf-8") as f: f.write(json.dumps({"url":u,"method":method,"status":status,"timestamp_utc":datetime.now(timezone.utc).isoformat()})+"\n")
   try: WEB_AUDIT.chmod(0o600)
   except OSError: pass
  except OSError: pass
 return page({"kind":"web","text":text_out[:100000]})

@app.post("/nmap")
def nmap():
 try:
  host=request.form.get("target","").strip()
  if not loopback(host): raise ValueError("Only localhost/loopback targets are allowed.")
  args=["nmap","-n","-Pn","-sT"]
  if request.form.get("profile")=="ports":
   ports=request.form.get("ports","")
   if not re.fullmatch(r"[0-9,-]+",ports): raise ValueError("Invalid port list.")
   args += ["-p",ports]
  else: args += ["--top-ports","100"]
  return page({"kind":"nmap","text":local(args+[host])})
 except Exception as e: flash(str(e)); return redirect(url_for("index"))
@app.post("/sqlmap")
def sqlmap():
 try:
  u=request.form.get("url","").strip(); p=urlparse(u)
  if p.scheme not in ("http","https") or not p.hostname or not loopback(p.hostname): raise ValueError("SQLmap URL must be HTTP(S) and point to localhost/loopback.")
  args=["sqlmap","-u",u,"--batch","--disable-coloring","--smart","--level=1","--risk=1","--timeout=8","--retries=0"]
  param=request.form.get("param","").strip()
  if param:
   if not re.fullmatch(r"[\w.-]{1,100}",param): raise ValueError("Invalid parameter name.")
   args += ["-p",param]
  return page({"kind":"sqlmap","text":local(args,180)})
 except Exception as e: flash(str(e)); return redirect(url_for("index"))
@app.post("/telnet")
def telnet():
 host=request.form.get("host","").strip(); user=request.form.get("username",""); password=request.form.get("password",""); command=request.form.get("command","").strip(); sid=uuid.uuid4().hex; log=f"{REMOTE_LOG_DIR}/{sid}.log"; port=int(request.form.get("port",23)); cleanup="not-created"; output=""; chunks=[]
 try:
  if not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}",host): raise ValueError("Invalid host format.")
  if not 1<=port<=65535: raise ValueError("Invalid port.")
  if len(command)>4000: raise ValueError("Command limit is 4,000 characters.")
  import shlex
  qlog=shlex.quote(log); qdir=shlex.quote(REMOTE_LOG_DIR)
  with socket.create_connection((host,port),timeout=10) as sock:
   sock.settimeout(1.2)
   def receive():
    data=[]; total=0
    while total<50000:
     try:
      part=sock.recv(min(4096,50000-total))
      if not part: break
      data.append(part); total+=len(part)
     except socket.timeout: break
    return b"".join(data).decode("utf-8","replace")
   def sendline(value): sock.sendall(value.encode("utf-8","replace")+b"\r\n")
   chunks.append(receive())
   if user: sendline(user); chunks.append(receive())
   if password: sendline(password); chunks.append(receive())
   # Create a unique marker; cleanup is limited to this exact session path.
   sendline(f"umask 077; mkdir -p -- {qdir} && printf '%s\n' {shlex.quote('session='+sid)} {shlex.quote('host='+host)} > {qlog} && echo __SESSION_LOG_CREATED__")
   marker=receive(); chunks.append(marker)
   created="__SESSION_LOG_CREATED__" in marker
   if created:
    cleanup="created"
    if command:
     sendline(command); chunks.append(receive())
    sendline(f"rm -f -- {qlog} && echo __SESSION_LOG_REMOVED__")
    removed=receive(); chunks.append(removed)
    cleanup="removed" if "__SESSION_LOG_REMOVED__" in removed else "cleanup-unconfirmed"
   else:
    cleanup="creation-unconfirmed"
    if command:
     sendline(command); chunks.append(receive())
    sendline("exit"); chunks.append(receive())
  output="".join(chunks).strip() or "Connected; no text received."
 except Exception as e:
  output=f"Telnet error: {e}"
 finally:
  try:
   DATA.mkdir(parents=True,exist_ok=True)
   entry={"session_id":sid,"host":host,"port":port,"username":user,"command_sha256":hashlib.sha256(command.encode()).hexdigest(),"remote_log_path":log,"cleanup":cleanup,"timestamp_utc":datetime.now(timezone.utc).isoformat()}
   with TELNET_AUDIT.open("a",encoding="utf-8") as f: f.write(json.dumps(entry)+"\n")
   try: TELNET_AUDIT.chmod(0o600)
   except OSError: pass
  except OSError:
   pass
 return page({"kind":"telnet","text":f"Session {sid}\nRemote log cleanup: {cleanup}\nLocal audit: {TELNET_AUDIT}\n\n{output[:100000]}"})
def valid_domain(value):
 value=(value or "").strip().rstrip(".")
 if len(value)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
  raise ValueError("Enter a valid domain name.")
 return value

@app.post("/osint/theharvester")
def osint_theharvester():
 try:
  domain=valid_domain(request.form.get("domain")); source=request.form.get("source","crtsh")
  if source not in {"crtsh","duckduckgo","bing","baidu"}: raise ValueError("Unsupported source.")
  output=local([tool_path("theHarvester"),"-d",domain,"-b",source],timeout=180)
  return page({"kind":"theharvester","text":output})
 except Exception as e: return page({"kind":"theharvester","text":f"theHarvester failed: {e}"})

@app.post("/osint/sherlock")
def osint_sherlock():
 try:
  username=request.form.get("username","").strip()
  if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}",username): raise ValueError("Use 1–64 letters, digits, dots, underscores, or hyphens.")
  output=local([tool_path("sherlock"),username,"--print-found","--timeout","10"],timeout=240)
  return page({"kind":"sherlock","text":output})
 except Exception as e: return page({"kind":"sherlock","text":f"Sherlock failed: {e}"})

@app.post("/osint/dnsrecon")
def osint_dnsrecon():
 try:
  domain=valid_domain(request.form.get("domain"))
  output=local([tool_path("dnsrecon"),"-d",domain,"-t","std"],timeout=180)
  return page({"kind":"dnsrecon","text":output})
 except Exception as e: return page({"kind":"dnsrecon","text":f"DNSrecon failed: {e}"})

@app.post("/osint/exiftool")
def osint_exiftool():
 try:
  uploaded=request.files.get("metadata_file")
  if not uploaded or not uploaded.filename: raise ValueError("Choose a file first.")
  import tempfile
  with tempfile.TemporaryDirectory(prefix="securelab-exif-") as td:
   staged=Path(td)/"input_file"
   uploaded.save(staged)
   if staged.stat().st_size>100*1024*1024: raise ValueError("File exceeds 100 MB limit.")
   output=local([tool_path("exiftool"),"-a","-G1","-s",str(staged)],timeout=90)
  return page({"kind":"exiftool","text":output})
 except Exception as e: return page({"kind":"exiftool","text":f"ExifTool failed: {e}"})

@app.post("/osint/spiderfoot")
def osint_spiderfoot():
 found=shutil.which("sf.py") or shutil.which("spiderfoot") or shutil.which("sf")
 text=(f"SpiderFoot command found: {found}\nLaunch it using the official instructions and open its local interface." if found else "SpiderFoot was not found on PATH. Install it separately using its official project instructions.")
 return page({"kind":"spiderfoot","text":text})

@app.post("/variant")
def variant():
 try:
  src=request.form.get("source","")
  if len(src)>200000: raise ValueError("Source too large.")
  return page({"kind":"variant","text":ast.unparse(ast.parse(src))+"\n"})
 except Exception as e: flash(f"Variant error: {e}"); return redirect(url_for("index"))
if __name__=="__main__":
 DATA.mkdir(parents=True,exist_ok=True)
 app.run(host="127.0.0.1",port=5001,debug=False)
