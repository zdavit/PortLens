# TODO

## Low Priority

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
- [x] Secure file creation — atomic file writes with `0o600` permissions via `os.open()`; hardened log directory
- [x] CSV formula injection — sanitize network-sourced fields in CSV export to prevent spreadsheet formula execution
- [x] Sanitize AI output — strip control characters and ANSI escapes from Ollama responses
- [x] Firewall rule shell safety — whitelist-based sanitization for service names in generated shell commands
- [x] Validate interactive target immediately — run `validate_target()` on input instead of deferring to scan time
- [x] Cap AI response size — limit reads from Ollama to 1 MB to prevent unbounded memory usage
- [x] Validate history JSON schema — check required keys (`timestamp`, `target`, `ports`, `hosts`) and file size on load
- [x] Expanded regression tests — cover validation, AI request handling, history loading, HTML/CSV export, and mocked network-map scans
- [x] IPv6-aware defaults and sorting — support IPv6 default targets, subnet validation, and host ordering
- [x] Full AI HTML export — fill in missing per-service AI sections during HTML report generation
- [x] Scrollable diff viewer — show full scan diffs inside the dashboard history flow
- [x] Richer network map metadata — include highest risk plus vendor/MAC details when available
- [x] Protocol-safe AI caching — keep TCP and UDP analyses distinct in the dashboard and HTML reports
- [x] Deterministic scan normalization — merge overlapping port inputs, preserve non-contiguous chunks, and dedupe/sort final scan results
- [x] Bounded AI summary prompts — cap whole-scan AI prompts to the highest-priority services and fail cleanly on oversized responses
- [x] Smarter watch-mode history — only save automatic watch rescans when the results actually change
- [x] IPv6 firewall parity — generate `ip6tables` suggestions for local IPv6 scans while keeping remote-host safeguards intact
- [x] CLI HTML export — support `--export html` and `--export all` outside the interactive dashboard
- [x] Port-aware risk inference — use common port behavior and product fingerprints to classify `unknown` / `tcpwrapped` services more accurately
