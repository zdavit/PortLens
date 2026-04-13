# TODO

## Features

- [ ] **Network device mapping** — scan a subnet and display a table of all discovered hosts with hostname, OS guess (`nmap -O`), and open port count
- [ ] **Security score summary** — compute an overall risk score per host (e.g., "Host 192.168.1.5: 72/100") based on number and severity of open services
- [ ] **Scan scheduling / watch mode** — re-scan on a configurable interval and alert when something changes (new port opens, service disappears)
- [ ] **HTML/PDF report export** — generate a shareable security report from scan results + AI analysis
- [ ] **UDP scanning** — currently TCP-only; UDP would catch DNS (53), SNMP (161), DHCP (67/68)
- [ ] **Firewall rule suggestions** — based on open ports, generate `iptables`/`firewalld` rules to close unnecessary ones
- [ ] **Web interface** — Flask/FastAPI frontend with a browser-based dashboard instead of just the curses CLI

## Completed

- [x] Full port scanning (1-65535)
- [x] Chunked scanning with progress reporting
- [x] Fast scan flags (`-T4`, `--version-intensity 0`, `-n`)
- [x] Port range preset menu (quick, well-known, extended, full, common, custom)
- [x] 70+ service risk classifications
- [x] Version-aware risk overrides (OpenSSH, MySQL, PostgreSQL, Apache, vsftpd)
- [x] AI analysis with Overview, What is this, Risks, Actions sections
- [x] Colored section labels in AI analysis
- [x] Scan history (JSON auto-save, CSV export, diffing)
- [x] Structured logging to `logs/scanner.log`
- [x] Organized source code into `src/` folder
- [x] Updated README with full documentation
