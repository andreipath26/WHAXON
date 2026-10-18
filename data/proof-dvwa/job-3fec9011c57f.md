# Job 3fec9011c57f

- **Tool**: nmap
- **Target**: 172.17.0.3
- **Status**: finished  exit=0
- **Started**: 

## Findings (3)

- **[INFO]** `open_port` — 80/tcp open http Apache httpd 2.4.25 ((Debian))
- **[INFO]** `suggestion` — Nikto web scan on port 80
- **[INFO]** `suggestion` — Gobuster directory busting on port 80

## Next steps

- Nikto web scan on port 80  (tool: `nikto`, args: `-h http://127.0.0.1:80`)
- Gobuster directory busting on port 80  (tool: `gobuster`, args: `-u http://127.0.0.1:80 -w /usr/share/wordlists/dirb/common.txt`)
