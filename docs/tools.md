# Tools

The catalog at data/tools.json controls which tools are available and how they are invoked.

## Format

    {
      tools: [
        {
          id: nmap,
          name: Nmap,
          category: recon,
          binary: nmap,
          description: Network mapper,
          args: -sT -sV {target},
          package: nmap
        }
      ]
    }

Fields:

- id: key everywhere (API, adapters, reports)
- name: display name
- category: recon / web / exploit / test
- binary: executable name (resolved via PATH) or absolute path
- description: one-line summary
- args: argv template; {target} is substituted
- package: OS package name; used by whaxon install
- available: computed - true if binary is on PATH

Unknown keys in tools.json are silently dropped by catalog.load() - the Tool dataclass only accepts declared fields.

## Current tools

- nmap (nmap, recon)
- nikto (nikto, web)
- gobuster (gobuster, web)
- echo (/bin/echo, test)
- sqlmap (sqlmap, web)
- whois (whois, recon)
- dig (dig, recon)
- nuclei (nuclei, web)
- ffuf (ffuf, web)
- wpscan (wpscan, web)
- impacket (impacket-secretsdump, exploit)
- theharvester (theHarvester, recon)
- dnsrecon (dnsrecon, recon)
- netexec (netexec, recon)
- arjun (arjun, web)
- msf_sysinfo (session, msf_session)
- msf_getuid (session, msf_session)
- msf_hashdump (session, msf_session)
- ssh_cmd (session, ssh)
- smb_shares (session, smb)
- smb_ls (session, smb)
- wmi_exec (session, wmi)

## Adding a tool

1. Append an entry to data/tools.json.
2. Restart the server - the catalog loads at Core.__init__ and has no hot-reload.
3. Write an adapter if you want enriched output. See adapters.md.

## Checking availability

GET /api/tools reports available: true|false per tool via shutil.which(binary). If a tool shows false, install it or fix the binary field.

## Installing tools

whaxon install reads package from the catalog and invokes the system package manager.