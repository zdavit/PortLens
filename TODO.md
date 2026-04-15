# TODO

## Low Priority

- [ ] **Pin dependencies** — lock `python-nmap` to an exact version in `requirements.txt` and run `pip-audit` to catch known vulnerabilities
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
- [x] UDP scanning — TCP, UDP, and combined scanning with `--udp`, `--both` flags and `u` key toggle
- [x] Network device mapping — scan a subnet and display a table of all discovered hosts with hostname, OS guess, and open port count
- [x] Security score summary — compute an overall risk score per host based on number and severity of open services
- [x] Target input validation — reject targets with shell characters, require valid IP/CIDR/hostname, block strings starting with `-`
- [x] Restrict `--diff` file reads — only allow loading files from `scan_history/`
- [x] Scan data file permissions — `0700` directories, `0600` files for saved scan data
- [x] Sanitize service banners — strip control characters and ANSI escapes from nmap output
- [x] Scan scheduling / watch mode — auto-rescan on interval, alert when ports open/close or risks change
- [x] HTML report export — self-contained HTML security report with scores, port tables, and AI analysis
