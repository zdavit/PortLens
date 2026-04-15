# TODO

## High Priority

- [x] **Target input validation** — reject targets with shell characters, require valid IP/CIDR/hostname, block strings starting with `-` to prevent nmap option injection

## Medium Priority

- [ ] **Restrict `--diff` file reads** — only allow loading files from `scan_history/`, canonicalize paths to prevent arbitrary file reads (especially dangerous when running as root)
- [ ] **Scan data file permissions** — set `0700` on directories and `0600` on saved JSON/CSV files so scan results aren't world-readable
- [ ] **Sanitize service banners** — strip control characters and ANSI escapes from nmap output before displaying in terminal or sending to AI to prevent terminal escape injection
- [ ] **Scan scheduling / watch mode** — re-scan on a configurable interval and alert when something changes (new port opens, service disappears)
- [ ] **HTML/PDF report export** — generate a shareable security report from scan results + AI analysis

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
