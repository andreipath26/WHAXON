# Secure Lab Portable

Cross-platform Flask dashboard scaffold for Windows, Linux, and macOS. Build a native executable on each target OS; PyInstaller artifacts are OS/architecture-specific.

## Run from source

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
python app/secure_lab.py
```

Dashboard: `http://127.0.0.1:5001`.

## Build

- Linux/macOS: `./build/build_current.sh`
- Windows PowerShell: `py -3 -m venv .build-venv; .\.build-venv\Scripts\python -m pip install -r requirements.txt; .\.build-venv\Scripts\python -m PyInstaller --noconfirm --clean --onefile --name SecureLab --collect-all paramiko --collect-all flask app/secure_lab.py`
- GitHub Actions builds separate Windows, Linux, and macOS executables.

## Exploit-DB catalog: offline and online

- **Offline refresh:** Open the Catalog & updates card and upload a local `files_exploits.csv` or ZIP containing it. The importer checks expected CSV columns, record count, and size, then atomically replaces `secure_lab_data/catalog/files_exploits.csv` and writes `catalog_metadata.json` with its SHA-256.
- **Get a fresh catalog while online:** run `python scripts/fetch_catalog.py`. The downloaded CSV is saved to `data/files_exploits.csv`; it can then be included with a project bundle or imported in the UI. After that, searching works offline.
- **Manifest-based update check:** set `SECURE_LAB_UPDATE_MANIFEST_URL` to a trusted HTTPS JSON manifest URL, then use the update controls. The manifest must include `latest_version`; catalog updates require `catalog_url` and `catalog_sha256`. The downloader validates the checksum and CSV before atomically installing it. The app does not self-replace its executable.

Example manifest shape:

```json
{
  "latest_version": "1.2.0",
  "release_url": "https://example.org/releases/1.2.0",
  "catalog_version": "2026-09-26",
  "catalog_url": "https://example.org/files_exploits.csv",
  "catalog_sha256": "<64-character-lowercase-sha256>"
}
```

## Tool availability and redistribution

- **SQLmap:** `python scripts/fetch_sqlmap_source.py` downloads an upstream source ZIP into `third_party/` for staging. The app can use a `sqlmap` executable or launcher placed in `tools/` (or found on PATH). This project ZIP does not contain the SQLmap archive.
- **Nmap:** provide a compatible, locally installed `nmap` executable or place it in `tools/`. A native Nmap binary is not bundled here. Windows packet-capture dependencies and Nmap's own redistribution terms need separate review before redistribution.
- **Exploit-DB:** metadata CSV is fetched/imported separately; the entire exploit repository is not bundled.

The app is a local-use scaffold, not a signed/notarized release. Keep the UI bound to localhost. SSH/Telnet/HTTP/Nmap/SQLmap actions should only be used on systems and services you are authorized to access. Telnet is unencrypted.


## OSINT modules

The dashboard includes dedicated in-app panels for **theHarvester**, **Sherlock**, **DNSrecon**, **ExifTool**, and a **SpiderFoot availability** panel. Panels switch within the same browser window.

Install each upstream tool separately and ensure its command is on `PATH` (or adapt the `tools/` folder integration for your platform): `theHarvester`, `sherlock`, `dnsrecon`, and `exiftool`. The corresponding panels invoke the installed commands with constrained options. ExifTool processes a user-selected file in a temporary directory. SpiderFoot is not driven by the app because it has its own web server and scan workflow; its panel only checks whether a command is installed. The app does not bundle these third-party tools or their data.

Use domain and username lookups only within your lawful, authorized scope. Public-site matches are indicators, not identity verification.

## Optional tool integration catalog

The **Tool Catalog** tab contains the candidate integrations discussed for the all-in-one platform. Each entry deliberately starts with Kali package status and upstream maintenance marked **Unverified**; package names are not guessed. This avoids suggesting an unrelated package or executing an untrusted installer.

- Registry: `data/tool_registry.json` (metadata only; no third-party tools are bundled).
- The dashboard supports filtering the candidate catalog by name/category.
- To mark a Kali package as verified, check the exact package name against Kali's official tool index (`https://www.kali.org/tools/`) and package tracker (`https://pkg.kali.org/`), and then record the exact package name and verification date in the registry.
- Check upstream maintenance from the project's official repository/release page; record the source and check date rather than treating a Kali package's existence as proof of active upstream development.
- **No automatic APT or upstream installation is enabled in this build.** Before adding it, use explicit user consent, an allowlisted verified package mapping, a preview/dry-run, and a logged result. Upstream projects should be installed from their official source with pinned versions in an isolated environment. Avoid adding third-party repositories to Kali's core APT source configuration.

Kali's official documentation explains its package tracker, tool index, and repository configuration: https://www.kali.org/docs/community/list-of-official-kali-sites/ and https://www.kali.org/docs/general-use/kali-apt-sources/.
# WHAXON
