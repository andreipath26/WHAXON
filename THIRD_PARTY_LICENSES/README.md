# Third-party license inventory

This directory tracks the third-party Python packages declared as runtime dependencies in `pyproject.toml`.

- `dependencies.csv` lists base and optional runtime dependencies and the license information recorded for them.
- `../THIRD_PARTY_NOTICES.md` provides the human-readable notice.
- External security tools (for example Nmap, Nikto, sqlmap, Metasploit, Nuclei, Gobuster and ffuf) are **not bundled** by this Python package and are not covered by this inventory.

## Maintenance requirements

1. Update the CSV and notices whenever a runtime dependency or version constraint changes.
2. Verify the license from the exact upstream release/distribution before redistributing binaries or bundling a dependency. A license label here is an inventory aid, not legal advice.
3. Review optional GUI and Metasploit dependencies separately before redistribution because their licensing terms can impose additional obligations.
4. Keep development-only dependencies in the development SBOM/inventory if a full build-environment inventory is required; they are intentionally not represented as shipped runtime dependencies here.
