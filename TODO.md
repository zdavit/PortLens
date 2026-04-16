# TODO

## High Priority

- [x] **Secure file creation** — use atomic file writes with restrictive permissions from the start instead of chmod after write; harden log directory permissions; add permission hardening to `firewall_rules.py` exports
- [x] **CSV formula injection** — sanitize service names, banners, and other network-sourced fields in CSV export to prevent spreadsheet formula execution (`=`, `+`, `-`, `@` prefixes)

## Medium Priority

- [ ] **Sanitize AI output** — strip control characters and ANSI escapes from Ollama responses before displaying in the terminal/TUI
- [ ] **Firewall rule shell safety** — sanitize service names interpolated into generated shell commands to prevent quote/metacharacter injection when users copy-paste
- [ ] **Validate interactive target immediately** — run `validate_target()` on user input before storing in `self.target` instead of waiting until scan time

## Low Priority

- [ ] **Cap AI response size** — limit the bytes read from Ollama `urlopen` to prevent unbounded memory usage
- [ ] **Validate history JSON schema** — check that loaded scan history files have the expected structure (`timestamp`, `target`, `ports`, `hosts`) before using them
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
- [x] Improved OS fingerprinting — `--osscan-guess` flag and OS-family aggregation for more accurate guesses
- [x] Scrollable details pane — `←/→` arrow keys to scroll the details/AI analysis pane with ▲/▼ indicators
- [x] Pin dependencies — lock `python-nmap` to an exact version in `requirements.txt` and run `pip-audit`
- [x] Firewall rule suggestions — generate `iptables`/`firewalld` rules to close unnecessary open ports
