# Tools

The catalog at data/tools.json controls which tools are available.

## Fields

    id           Short unique identifier
    name         Display name
    category     Grouping label
    binary       Executable (name on PATH or absolute path)
    description  One-line description
    args         Argument template

## Argument templates

{target} is replaced with the user's target. Split with shlex.split.

    "args": "-h {target} -nointeractive"

For target example.com, WHAXON runs:

    nikto -h example.com -nointeractive

The binary is never invoked through a shell. Shell metacharacters are
treated as literal arguments - this prevents command injection.

## Extra arguments

Every interface has an extra args field. Whatever the user types is
appended after the template:

    template:   nmap -sT {target}
    user extra: -sV -p 22,80
    final:      nmap -sT example.com -sV -p 22,80

## Built-in catalog

    nmap      Nmap       recon   -sT {target}
    nikto     Nikto      web     -h {target} -nointeractive
    gobuster  Gobuster   web     dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q --no-error
    sqlmap    SQLmap     web     -u {target} --batch --crawl=1 --level=1 --risk=1
    whois     WHOIS      recon   {target}
    dig       dig        recon   +short ANY {target}
    nuclei    Nuclei     web     -u {target} -silent -no-color -disable-update-check
    ffuf      ffuf       web     -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -s
    wpscan    WPScan     web     --url {target} --no-banner --no-update
    echo      Echo test  test    {target}

## Adding a tool

1. Ensure the binary is on PATH
2. Append an entry to data/tools.json
3. Save - the tool appears in every UI immediately

Example:

    {
      "id": "nslookup",
      "name": "nslookup",
      "category": "recon",
      "binary": "nslookup",
      "description": "DNS lookup",
      "args": "{target}"
    }

## Wordlists

gobuster and ffuf reference /usr/share/wordlists/dirb/common.txt by default.
On Kali this exists. Elsewhere, install dirb or seclists and change the
template path:

    sudo apt install seclists
    # use /usr/share/seclists/Discovery/Web-Content/common.txt
