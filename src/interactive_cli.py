import curses
import os
import re
import textwrap
import threading
import time
from queue import Empty, Queue

import network_map
import scan_history
import scanner


SPINNER_FRAMES = ["|", "/", "-", "\\"]
COLOR_ACCENT = 1
COLOR_SUCCESS = 2
COLOR_WARNING = 3
COLOR_DANGER = 4
COLOR_AI = 5
COLOR_SELECTION = 6
COLOR_PANEL = 7
COLOR_MUTED = 8

MARKDOWN_BOLD_RE = re.compile(r"\*\*(.*?)\*\*")
INLINE_CODE_RE = re.compile(r"`([^`]*)`")


class DashboardApp:
    def __init__(self, initial_target=None, initial_ports=None, initial_use_ai=True, initial_scan_mode="tcp"):
        self.target = initial_target or self._safe_default_target()
        self.ports = initial_ports or scanner.DEFAULT_PORT_RANGE
        self.use_ai = initial_use_ai
        self.scan_mode = initial_scan_mode
        self.status_message = "Press r to scan, m for network map, or ? for help."
        self.results = []
        self.error_message = ""
        self.selected_index = 0
        self.scroll_offset = 0
        self.running = False
        self.spinner_index = 0
        self.worker = None
        self.analysis_worker = None
        self.events = Queue()
        self.has_colors = False
        self.analysis_cache = {}
        self.analysis_errors = {}
        self.analysis_loading_key = None
        self.show_closed = False
        self.last_save_path = None
        self.network_map = []
        self.network_map_loading = False
        self.network_map_worker = None

    def _safe_default_target(self):
        try:
            return scanner.get_default_target()
        except scanner.ScannerError:
            return "localhost"

    def flatten_services(self):
        open_rows = []
        closed_rows = []
        for host_info in self.results:
            hostname = host_info["hostname"] or "N/A"
            for service in host_info.get("ports", host_info["services"]):
                row = {
                    "host": host_info["host"],
                    "hostname": hostname,
                    "port": service["port"],
                    "protocol": service.get("protocol", "tcp"),
                    "service": service["service"],
                    "product": scanner.format_product_name(service),
                    "risk": service.get("risk", "Unknown"),
                    "state": service.get("state", "open"),
                }
                if row["state"] == "open":
                    open_rows.append(row)
                elif self.show_closed and row["state"] == "closed":
                    closed_rows.append(row)

        closed_priority = {
            port: index for index, port in enumerate(scanner.COMMON_EDUCATIONAL_PORTS)
        }
        closed_rows.sort(
            key=lambda row: (
                0 if row["port"] in closed_priority else 1,
                closed_priority.get(row["port"], row["port"]),
                row["host"],
                row["port"],
            )
        )
        return open_rows + closed_rows[: scanner.CLOSED_PORT_DISPLAY_LIMIT]

    def selected_service(self):
        services = self.flatten_services()
        if not services:
            return None
        return services[self.selected_index]

    def service_key(self, service):
        return (service["host"], service["port"], service["service"], service.get("state", "open"))

    def start_scan(self):
        if self.running:
            return

        self.running = True
        self.spinner_index = 0
        self.results = []
        self.error_message = ""
        self.selected_index = 0
        self.scroll_offset = 0
        self.analysis_cache = {}
        self.analysis_errors = {}
        self.analysis_loading_key = None
        self.status_message = f"Scanning {self.target} on ports {self.ports}..."
        self.worker = threading.Thread(target=self._scan_worker, daemon=True)
        self.worker.start()

    def _scan_worker(self):
        def on_progress(scanned, total, message=None):
            if message:
                self.events.put(("status", message))
            else:
                self.events.put(("progress", (scanned, total)))

        try:
            mode_label = self.scan_mode.upper()
            self.events.put(("status", f"Scanning {self.target} on ports {self.ports} ({mode_label})..."))
            results = scanner.scan_network(
                self.target, self.ports, announce=False, progress_callback=on_progress,
                scan_mode=self.scan_mode,
            )
            self.events.put(("results", results))
            self.events.put(("done", None))
        except scanner.ScannerError as exc:
            self.events.put(("error", str(exc)))
            self.events.put(("done", None))

    def start_network_map(self):
        if self.running or self.network_map_loading:
            return
        try:
            subnet = scanner.get_default_target()
        except scanner.ScannerError as exc:
            self.status_message = f"Could not detect subnet: {exc}"
            return
        self.network_map_loading = True
        self.network_map_subnet = subnet
        self.status_message = f"Mapping network hosts on {subnet} (requires root)..."
        self.network_map_worker = threading.Thread(target=self._network_map_worker, args=(subnet,), daemon=True)
        self.network_map_worker.start()

    def _network_map_worker(self, subnet):
        try:
            hosts = network_map.scan_network_map(subnet)
            self.events.put(("network_map", hosts))
        except scanner.ScannerError as exc:
            self.events.put(("network_map_error", str(exc)))

    def ensure_selected_analysis(self):
        if self.running or not self.use_ai or self.analysis_loading_key is not None:
            return

        service = self.selected_service()
        if service is None or service.get("state") != "open":
            return

        key = self.service_key(service)
        if key in self.analysis_cache or key in self.analysis_errors:
            return

        self.analysis_loading_key = key
        self.analysis_worker = threading.Thread(
            target=self._analysis_worker,
            args=(service,),
            daemon=True,
        )
        self.analysis_worker.start()

    def _analysis_worker(self, service):
        key = self.service_key(service)
        try:
            analysis = scanner.get_service_ai_analysis(service, announce=False)
        except scanner.AIAnalysisError as exc:
            self.events.put(("service_ai_warning", (key, str(exc))))
        else:
            self.events.put(("service_analysis", (key, analysis)))

    def process_events(self):
        changed = False
        while True:
            try:
                event, payload = self.events.get_nowait()
            except Empty:
                break

            changed = True
            if event == "progress":
                scanned, total = payload
                pct = int(scanned / total * 100) if total else 100
                self.status_message = f"Scanning... {scanned}/{total} chunks ({pct}%)"
            elif event == "status":
                self.status_message = payload
            elif event == "results":
                self.results = payload
                self.selected_index = 0
                self.scroll_offset = 0
                total_services = len(self.flatten_services())
                try:
                    path = scan_history.export_json(payload, self.target, self.ports)
                    self.last_save_path = path
                    save_msg = " Saved."
                except OSError:
                    save_msg = ""
                self.status_message = (
                    f"Scan finished: {len(payload)} host(s), {total_services} open service(s).{save_msg}"
                )
                self.ensure_selected_analysis()
            elif event == "service_analysis":
                key, analysis = payload
                self.analysis_cache[key] = analysis
                if self.analysis_loading_key == key:
                    self.analysis_loading_key = None
            elif event == "service_ai_warning":
                key, warning = payload
                self.analysis_errors[key] = warning
                if self.analysis_loading_key == key:
                    self.analysis_loading_key = None
            elif event == "network_map":
                self.network_map = payload
                self.network_map_loading = False
                self.status_message = f"Network map: {len(payload)} host(s) discovered."
            elif event == "network_map_error":
                self.network_map_loading = False
                self.status_message = f"Network map failed: {payload}"
            elif event == "error":
                self.error_message = payload
                self.status_message = "Scan failed."
            elif event == "done":
                self.running = False
                self.ensure_selected_analysis()

        self.ensure_selected_analysis()
        return changed

    def move_selection(self, delta):
        services = self.flatten_services()
        if not services:
            self.selected_index = 0
            self.scroll_offset = 0
            return

        self.selected_index = max(0, min(self.selected_index + delta, len(services) - 1))
        self.ensure_selected_analysis()

    def cycle_spinner(self):
        if self.running or self.analysis_loading_key is not None or self.network_map_loading:
            self.spinner_index = (self.spinner_index + 1) % len(SPINNER_FRAMES)

    def init_colors(self):
        self.has_colors = curses.has_colors()
        if not self.has_colors:
            return

        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(COLOR_ACCENT, curses.COLOR_CYAN, -1)
        curses.init_pair(COLOR_SUCCESS, curses.COLOR_GREEN, -1)
        curses.init_pair(COLOR_WARNING, curses.COLOR_YELLOW, -1)
        curses.init_pair(COLOR_DANGER, curses.COLOR_RED, -1)
        curses.init_pair(COLOR_AI, curses.COLOR_MAGENTA, -1)
        curses.init_pair(COLOR_SELECTION, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(COLOR_PANEL, curses.COLOR_BLUE, -1)
        curses.init_pair(COLOR_MUTED, curses.COLOR_WHITE, -1)

    def color(self, pair_id, fallback=0):
        if self.has_colors:
            return curses.color_pair(pair_id)
        return fallback

    def row_attr(self, service, selected=False):
        if selected:
            return self.color(COLOR_SELECTION, curses.A_REVERSE) | curses.A_BOLD
        if service.get("state") == "closed":
            return self.color(COLOR_MUTED)
        risk = service.get("risk", "Unknown")
        if risk == "Critical":
            return self.color(COLOR_DANGER) | curses.A_BOLD
        if risk == "High":
            return self.color(COLOR_WARNING) | curses.A_BOLD
        if risk == "Medium":
            return self.color(COLOR_AI) | curses.A_BOLD
        if risk == "Low":
            return self.color(COLOR_SUCCESS) | curses.A_BOLD
        return self.color(COLOR_MUTED)

    def status_attr(self):
        if self.error_message:
            return self.color(COLOR_DANGER) | curses.A_BOLD
        if self.running:
            return self.color(COLOR_WARNING) | curses.A_BOLD
        if self.analysis_loading_key is not None:
            return self.color(COLOR_AI) | curses.A_BOLD
        if self.analysis_errors:
            return self.color(COLOR_WARNING) | curses.A_BOLD
        if self.results:
            return self.color(COLOR_SUCCESS) | curses.A_BOLD
        return self.color(COLOR_ACCENT) | curses.A_BOLD

    def run(self, stdscr):
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)
        stdscr.nodelay(True)

        self.init_colors()

        while True:
            self.process_events()
            self.draw(stdscr)
            self.cycle_spinner()

            key = stdscr.getch()
            if key == -1:
                time.sleep(0.08)
                continue

            if key in (ord("q"), ord("Q")):
                return 0
            if key == ord("?"):
                self.show_help(stdscr)
            elif key in (ord("r"), ord("R")):
                self.start_scan()
            elif key in (ord("o"), ord("O")) and not self.running:
                self.show_closed = not self.show_closed
                mode = "open + closed" if self.show_closed else "open only"
                self.status_message = f"Port view set to {mode}."
                self.selected_index = 0
                self.scroll_offset = 0
                self.ensure_selected_analysis()
            elif key in (ord("a"), ord("A")) and not self.running:
                self.use_ai = not self.use_ai
                state = "enabled" if self.use_ai else "disabled"
                self.status_message = f"AI analysis {state}."
                if self.use_ai:
                    self.ensure_selected_analysis()
            elif key in (ord("t"), ord("T")) and not self.running:
                updated = self.prompt_input(stdscr, "Target", self.target)
                if updated is not None:
                    self.target = updated.strip() or self.target
                    self.status_message = f"Target set to {self.target}."
            elif key in (ord("f"), ord("F")) and not self.running:
                self.ports = "1-65535"
                self.status_message = "Ports set to 1-65535 (full scan). Press r to scan."
            elif key in (ord("p"), ord("P")) and not self.running:
                choice = self.prompt_port_menu(stdscr)
                if choice is not None:
                    try:
                        self.ports = scanner.validate_ports_spec(choice)
                    except scanner.ScannerError as exc:
                        self.status_message = str(exc)
                    else:
                        self.status_message = f"Ports set to {self.ports}."
            elif key in (ord("d"), ord("D")) and not self.running:
                try:
                    self.target = scanner.get_default_target()
                except scanner.ScannerError as exc:
                    self.error_message = str(exc)
                    self.status_message = "Could not detect a default subnet."
                else:
                    self.status_message = f"Target reset to {self.target}."
            elif key in (ord("e"), ord("E")) and not self.running and self.results:
                try:
                    csv_path = scan_history.export_csv(self.results, self.target, self.ports)
                    self.status_message = f"CSV exported: {os.path.basename(csv_path)}"
                except OSError as exc:
                    self.status_message = f"Export failed: {exc}"
            elif key in (ord("u"), ord("U")) and not self.running:
                modes = list(scanner.SCAN_MODES)
                current = modes.index(self.scan_mode) if self.scan_mode in modes else 0
                next_mode = modes[(current + 1) % len(modes)]
                if next_mode in ("udp", "both") and os.geteuid() != 0:
                    self.status_message = f"{next_mode.upper()} scanning requires root. Run with sudo."
                else:
                    self.scan_mode = next_mode
                    self.status_message = f"Scan mode set to {self.scan_mode.upper()}. Press r to scan."
            elif key in (ord("m"), ord("M")) and not self.running:
                if self.network_map_loading:
                    pass
                elif self.network_map:
                    self.show_network_map(stdscr)
                else:
                    self.start_network_map()
            elif key in (ord("h"), ord("H")) and not self.running:
                self.show_history_menu(stdscr)
            elif key == curses.KEY_UP:
                self.move_selection(-1)
            elif key == curses.KEY_DOWN:
                self.move_selection(1)

    def show_help(self, stdscr):
        HELP_LINES = [
            ("r", "Run a scan"),
            ("t", "Edit target host or subnet"),
            ("p", "Open port range menu"),
            ("f", "Set ports to 1-65535 (full scan)"),
            ("d", "Reset target to auto-detected subnet"),
            ("u", "Cycle scan mode (TCP / UDP / Both)"),
            ("m", "Network map (discover hosts with OS detection)"),
            ("o", "Toggle open-only / open+closed view"),
            ("a", "Toggle AI analysis on/off"),
            ("e", "Export current results to CSV"),
            ("h", "Browse scan history / diff"),
            ("↑/↓", "Navigate services"),
            ("q", "Quit"),
        ]

        height, width = stdscr.getmaxyx()
        box_height = len(HELP_LINES) + 5
        box_width = min(55, max(40, width - 4))
        start_y = max(1, (height - box_height) // 2)
        start_x = max(2, (width - box_width) // 2)
        window = curses.newwin(box_height, box_width, start_y, start_x)
        window.keypad(True)

        window.erase()
        if self.has_colors:
            window.attron(self.color(COLOR_PANEL))
            window.border()
            window.attroff(self.color(COLOR_PANEL))
        else:
            window.border()
        window.addnstr(0, 2, " Keybindings ", box_width - 4,
                       self.color(COLOR_ACCENT) | curses.A_BOLD)

        for i, (key, desc) in enumerate(HELP_LINES):
            window.addnstr(2 + i, 3, f"{key:>5}  {desc}", box_width - 6,
                           self.color(COLOR_MUTED))

        window.addnstr(box_height - 2, 3, "Press any key to close",
                       box_width - 6, self.color(COLOR_MUTED))
        window.refresh()
        window.nodelay(False)
        window.getch()

    def prompt_port_menu(self, stdscr):
        PORT_PRESETS = [
            ("1-100", "Quick scan (ports 1-100)"),
            ("1-1024", "Well-known ports (1-1024)"),
            ("1-10000", "Extended range (1-10000)"),
            ("1-65535", "Full scan (all ports)"),
            ("21,22,23,25,53,80,110,143,443,3306,3389,5432,8080", "Common services only"),
        ]
        height, width = stdscr.getmaxyx()
        menu_items = len(PORT_PRESETS) + 1  # +1 for custom
        box_height = menu_items + 6
        box_width = min(60, max(40, width - 4))
        start_y = max(1, (height - box_height) // 2)
        start_x = max(2, (width - box_width) // 2)
        window = curses.newwin(box_height, box_width, start_y, start_x)
        window.keypad(True)

        selected = 0
        total = len(PORT_PRESETS) + 1

        while True:
            window.erase()
            if self.has_colors:
                window.attron(self.color(COLOR_PANEL))
                window.border()
                window.attroff(self.color(COLOR_PANEL))
            else:
                window.border()
            window.addnstr(0, 2, " Port Range ", box_width - 4, self.color(COLOR_ACCENT) | curses.A_BOLD)
            window.addnstr(2, 2, "Select a range or enter a custom one:", box_width - 4, self.color(COLOR_MUTED))

            for i, (value, label) in enumerate(PORT_PRESETS):
                attr = self.color(COLOR_SELECTION, curses.A_REVERSE) | curses.A_BOLD if i == selected else curses.A_NORMAL
                window.addnstr(4 + i, 3, f" {label} ", box_width - 6, attr)

            custom_attr = self.color(COLOR_SELECTION, curses.A_REVERSE) | curses.A_BOLD if selected == total - 1 else curses.A_NORMAL
            window.addnstr(4 + len(PORT_PRESETS), 3, " Custom range... ", box_width - 6, custom_attr)
            window.refresh()

            key = window.getch()
            if key in (ord("q"), ord("Q"), 27):  # q or Escape
                return None
            elif key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % total
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % total
            elif key in (10, curses.KEY_ENTER):  # Enter
                if selected < len(PORT_PRESETS):
                    return PORT_PRESETS[selected][0]
                else:
                    del window
                    return self.prompt_input(stdscr, "Custom Ports", self.ports)

    def show_history_menu(self, stdscr):
        entries = scan_history.list_history()
        if not entries:
            self.status_message = "No scan history found."
            return

        display_entries = entries[:20]
        height, width = stdscr.getmaxyx()
        box_height = min(len(display_entries) + 5, height - 4)
        box_width = min(75, max(50, width - 4))
        start_y = max(1, (height - box_height) // 2)
        start_x = max(2, (width - box_width) // 2)
        window = curses.newwin(box_height, box_width, start_y, start_x)
        window.keypad(True)

        selected = 0
        view_height = box_height - 5

        while True:
            window.erase()
            if self.has_colors:
                window.attron(self.color(COLOR_PANEL))
                window.border()
                window.attroff(self.color(COLOR_PANEL))
            else:
                window.border()
            window.addnstr(0, 2, " Scan History ", box_width - 4,
                           self.color(COLOR_ACCENT) | curses.A_BOLD)
            window.addnstr(2, 2, "Select a scan to diff against current results:",
                           box_width - 4, self.color(COLOR_MUTED))

            visible = display_entries[:view_height]
            for i, entry in enumerate(visible):
                label = (
                    f"{entry['timestamp']}  {entry['target']:<16} "
                    f"{entry['open_count']} open"
                )
                attr = (self.color(COLOR_SELECTION, curses.A_REVERSE) | curses.A_BOLD
                        if i == selected else curses.A_NORMAL)
                window.addnstr(4 + i, 3, f" {label} ", box_width - 6, attr)
            window.refresh()

            key = window.getch()
            if key in (ord("q"), ord("Q"), 27):
                return
            elif key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(visible)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(visible)
            elif key in (10, curses.KEY_ENTER):
                chosen = visible[selected]
                del window
                if not self.results:
                    self.status_message = "Run a scan first before diffing."
                    return
                try:
                    old_scan = scan_history.load_scan(chosen["filepath"])
                    diff = scan_history.diff_scans(old_scan["hosts"], self.results)
                    self.status_message = scan_history.format_diff(diff).split("\n")[0]
                    self._last_diff = scan_history.format_diff(diff)
                except (OSError, KeyError) as exc:
                    self.status_message = f"Diff failed: {exc}"
                return

    def show_network_map(self, stdscr):
        hosts = self.network_map
        if not hosts:
            self.status_message = "No network map data. Press m to scan."
            return

        height, width = stdscr.getmaxyx()
        box_height = min(len(hosts) + 7, height - 4)
        box_width = min(100, max(70, width - 4))
        start_y = max(1, (height - box_height) // 2)
        start_x = max(2, (width - box_width) // 2)
        window = curses.newwin(box_height, box_width, start_y, start_x)
        window.keypad(True)

        selected = 0
        scroll = 0
        view_height = box_height - 7

        while True:
            window.erase()
            if self.has_colors:
                window.attron(self.color(COLOR_PANEL))
                window.border()
                window.attroff(self.color(COLOR_PANEL))
            else:
                window.border()
            window.addnstr(0, 2, " Network Map ", box_width - 4,
                           self.color(COLOR_ACCENT) | curses.A_BOLD)
            subnet = getattr(self, "network_map_subnet", self.target)
            summary = f"{len(hosts)} host(s) discovered on {subnet}"
            window.addnstr(2, 2, summary, box_width - 4, self.color(COLOR_MUTED))

            header = f"  {'Host':<17} {'Hostname':<16} {'State':<7} {'Ports':<6} OS Guess"
            window.addnstr(4, 2, header, box_width - 4,
                           self.color(COLOR_ACCENT) | curses.A_BOLD)

            if selected < scroll:
                scroll = selected
            elif selected >= scroll + view_height:
                scroll = selected - view_height + 1

            visible = hosts[scroll:scroll + view_height]
            for i, host in enumerate(visible):
                actual = scroll + i
                os_col = host["os_guess"][:box_width - 55]
                line = (
                    f"  {host['host']:<17} "
                    f"{(host['hostname'] or 'N/A')[:15]:<16} "
                    f"{host['state']:<7} "
                    f"{host['open_port_count']:<6} "
                    f"{os_col}"
                )
                if actual == selected:
                    attr = self.color(COLOR_SELECTION, curses.A_REVERSE) | curses.A_BOLD
                elif host["open_port_count"] == 0:
                    attr = self.color(COLOR_MUTED)
                elif host["open_port_count"] >= 5:
                    attr = self.color(COLOR_WARNING) | curses.A_BOLD
                else:
                    attr = self.color(COLOR_SUCCESS)
                window.addnstr(5 + i, 2, line, box_width - 4, attr)

            footer = "↑↓ navigate | Enter select target | r rescan | q close"
            window.addnstr(box_height - 2, 2, footer, box_width - 4,
                           self.color(COLOR_MUTED))
            window.refresh()

            key = window.getch()
            if key in (ord("q"), ord("Q"), 27):
                return
            elif key in (curses.KEY_UP, ord("k")):
                selected = (selected - 1) % len(hosts)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = (selected + 1) % len(hosts)
            elif key in (10, curses.KEY_ENTER):
                chosen = hosts[selected]
                self.target = chosen["host"]
                self.status_message = f"Target set to {self.target}. Press r to scan."
                return
            elif key in (ord("r"), ord("R")):
                del window
                self.network_map = []
                self.start_network_map()
                return

    def prompt_input(self, stdscr, label, current_value):
        height, width = stdscr.getmaxyx()
        box_width = min(max(50, len(current_value) + 10), max(40, width - 4))
        box_height = 7
        start_y = max(1, (height - box_height) // 2)
        start_x = max(2, (width - box_width) // 2)
        window = curses.newwin(box_height, box_width, start_y, start_x)
        window.keypad(True)
        window.border()
        title = f" {label} "
        if self.has_colors:
            window.attron(self.color(COLOR_PANEL))
            window.border()
            window.attroff(self.color(COLOR_PANEL))
        window.addnstr(0, 2, title, box_width - 4, self.color(COLOR_ACCENT) | curses.A_BOLD)
        window.addnstr(
            2,
            2,
            f"Enter {label.lower()} and press Enter.",
            box_width - 4,
            self.color(COLOR_MUTED),
        )
        window.addnstr(4, 2, current_value, box_width - 4, self.color(COLOR_AI) | curses.A_BOLD)
        window.refresh()

        curses.echo()
        curses.curs_set(1)
        window.move(4, 2 + min(len(current_value), box_width - 5))
        raw_value = window.getstr(4, 2, box_width - 4)
        curses.noecho()
        curses.curs_set(0)

        if raw_value is None:
            return None
        return raw_value.decode("utf-8", errors="ignore")

    def draw(self, stdscr):
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 20 or width < 80:
            stdscr.addnstr(0, 0, "Resize the terminal to at least 80x20 to use the dashboard.", width - 1)
            stdscr.refresh()
            return

        header = " Smart Network Scanner Dashboard "
        scan_state = "IDLE"
        if self.running:
            scan_state = f"SCANNING {SPINNER_FRAMES[self.spinner_index]}"
        elif self.network_map_loading:
            scan_state = f"MAPPING {SPINNER_FRAMES[self.spinner_index]}"
        elif self.analysis_loading_key is not None:
            scan_state = f"ANALYZING {SPINNER_FRAMES[self.spinner_index]}"
        elif self.error_message:
            scan_state = "ERROR"
        stdscr.hline(0, 0, " ", width, self.color(COLOR_PANEL))
        stdscr.addnstr(0, 2, header, width - 4, self.color(COLOR_ACCENT) | curses.A_BOLD)
        stdscr.addnstr(
            0,
            max(2, width - len(scan_state) - 3),
            scan_state,
            len(scan_state),
            self.status_attr(),
        )

        top_height = 7
        content_top = top_height + 1
        body_height = height - content_top - 2
        left_width = max(40, width // 2)
        right_width = width - left_width - 1

        self.draw_box(stdscr, 1, 0, top_height, width, "Controls")
        controls = [
            f"Target: {self.target}",
            f"Ports: {self.ports}  |  Mode: {self.scan_mode.upper()}",
            f"View: {'OPEN + CLOSED' if self.show_closed else 'OPEN ONLY'}  |  AI: {'ON' if self.use_ai else 'OFF'}",
            f"Status: {self.status_message}",
        ]
        control_attrs = [
            self.color(COLOR_ACCENT) | curses.A_BOLD,
            self.color(COLOR_PANEL) | curses.A_BOLD,
            self.color(COLOR_MUTED) | curses.A_BOLD,
            self.status_attr(),
        ]
        for index, (line, attr) in enumerate(zip(controls, control_attrs)):
            stdscr.addnstr(2 + index, 2, line, width - 4, attr)

        ports_title = "Ports" if self.show_closed else "Open Services"
        self.draw_box(stdscr, content_top, 0, body_height, left_width, ports_title)
        self.draw_services_pane(stdscr, content_top, 0, body_height, left_width)

        self.draw_box(stdscr, content_top, left_width, body_height, right_width + 1, "Details")
        self.draw_detail_pane(stdscr, content_top, left_width, body_height, right_width + 1)

        footer = "? help | r scan | q quit"
        stdscr.hline(height - 1, 0, " ", width, self.color(COLOR_PANEL))
        stdscr.addnstr(height - 1, 2, footer, width - 4, self.color(COLOR_MUTED))
        stdscr.refresh()

    def draw_box(self, stdscr, start_y, start_x, box_height, box_width, title):
        if box_height < 3 or box_width < 10:
            return
        max_y, max_x = stdscr.getmaxyx()
        bottom = min(max_y - 1, start_y + box_height - 1)
        right = min(max_x - 1, start_x + box_width - 1)
        panel_attr = self.color(COLOR_PANEL)
        stdscr.hline(start_y, start_x + 1, curses.ACS_HLINE, max(1, right - start_x - 1), panel_attr)
        stdscr.hline(bottom, start_x + 1, curses.ACS_HLINE, max(1, right - start_x - 1), panel_attr)
        stdscr.vline(start_y + 1, start_x, curses.ACS_VLINE, max(1, bottom - start_y - 1), panel_attr)
        stdscr.vline(start_y + 1, right, curses.ACS_VLINE, max(1, bottom - start_y - 1), panel_attr)
        stdscr.addch(start_y, start_x, curses.ACS_ULCORNER, panel_attr)
        stdscr.addch(start_y, right, curses.ACS_URCORNER, panel_attr)
        stdscr.addch(bottom, start_x, curses.ACS_LLCORNER, panel_attr)
        stdscr.addch(bottom, right, curses.ACS_LRCORNER, panel_attr)
        stdscr.addnstr(
            start_y,
            start_x + 2,
            f" {title} ",
            max(1, right - start_x - 3),
            self.color(COLOR_ACCENT) | curses.A_BOLD,
        )

    def draw_services_pane(self, stdscr, start_y, start_x, box_height, box_width):
        services = self.flatten_services()
        view_height = box_height - 3
        inner_width = box_width - 2
        if not services:
            empty_message = self.error_message or "No scan results yet. Press r to run a scan."
            stdscr.addnstr(
                start_y + 2,
                start_x + 2,
                empty_message,
                inner_width - 2,
                self.status_attr() if self.error_message else self.color(COLOR_MUTED),
            )
            return

        max_visible = max(1, view_height - 1)
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + max_visible:
            self.scroll_offset = self.selected_index - max_visible + 1

        header = "Port       Service       State    Host"
        stdscr.addnstr(
            start_y + 1,
            start_x + 2,
            header,
            inner_width - 2,
            self.color(COLOR_ACCENT) | curses.A_BOLD,
        )
        visible_services = services[self.scroll_offset : self.scroll_offset + max_visible]
        for row, service in enumerate(visible_services, start=0):
            actual_index = self.scroll_offset + row
            selected = actual_index == self.selected_index
            port_label = f"{service['port']}/{service['protocol']}"
            line = (
                f"{port_label:<10} "
                f"{service['service'][:12]:<12} "
                f"{service['state'][:8]:<8} "
                f"{service['host'][:inner_width - 37]}"
            )
            attrs = self.row_attr(service, selected=selected)
            stdscr.addnstr(start_y + 2 + row, start_x + 2, line, inner_width - 2, attrs)

    def format_analysis_lines(self, text, width):
        formatted_lines = []
        previous_blank = False
        in_code_block = False

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("```"):
                in_code_block = not in_code_block
                continue

            if in_code_block:
                continue

            if not line:
                if formatted_lines and not previous_blank:
                    formatted_lines.append("")
                previous_blank = True
                continue

            line = MARKDOWN_BOLD_RE.sub(r"\1", line)
            line = INLINE_CODE_RE.sub(r"\1", line)
            line = re.sub(r"^#{1,6}\s*", "", line)
            line = re.sub(r"^\*\s+", "- ", line)
            line = re.sub(r"^[-]{2,}\s*", "- ", line)

            prefix = ""
            if line.startswith("- "):
                prefix = "- "
                body = line[2:].strip()
            else:
                match = re.match(r"^(\d+\.\s+)(.*)$", line)
                if match:
                    prefix = match.group(1)
                    body = match.group(2).strip()
                else:
                    body = line

            if not body:
                if formatted_lines and not previous_blank:
                    formatted_lines.append("")
                previous_blank = True
                continue

            wrapped = textwrap.wrap(
                body,
                width=max(20, width - len(prefix)),
                initial_indent=prefix,
                subsequent_indent=" " * len(prefix),
                break_long_words=False,
                break_on_hyphens=False,
            )
            formatted_lines.extend(wrapped or [prefix + body])
            previous_blank = False

        while formatted_lines and not formatted_lines[-1]:
            formatted_lines.pop()

        return formatted_lines

    def draw_detail_pane(self, stdscr, start_y, start_x, box_height, box_width):
        services = self.flatten_services()
        content_y = start_y + 1
        content_x = start_x + 2
        content_width = box_width - 3
        content_height = box_height - 2
        lines = []
        selected_service = None
        selected_key = None

        if services:
            selected_service = services[self.selected_index]
            selected_key = self.service_key(selected_service)
            lines.append(f"Host: {selected_service['host']} ({selected_service['hostname']})")
            host_info = next((h for h in self.results if h["host"] == selected_service["host"]), None)
            if host_info:
                score = scanner.compute_host_score(host_info)
                lines.append(f"Security Score: {score}/100 ({scanner.score_label(score)})")
            lines.append(f"Port: {selected_service['port']}")
            lines.append(f"Service: {selected_service['service']}")
            lines.append(f"State: {selected_service['state']}")
            if selected_service["state"] == "open":
                lines.append(f"Product: {selected_service['product']}")
                lines.append(f"Risk: {selected_service['risk']}")
            lines.append("")

        if selected_service and selected_service["state"] == "closed":
            lines.append("Closed Port Note")
            lines.append("")
            lines.extend(
                self.format_analysis_lines(
                    "Overview: No service responded on this port.\n"
                    "Risks:\n"
                    "- A closed port usually means the service is not exposed, which is good.\n"
                    "- If you expected something here, the service may be stopped or blocked by a firewall.\n"
                    "Actions:\n"
                    "1. Leave it closed if you do not need that service.\n"
                    "2. If you expected it open, verify the daemon and firewall rules.\n"
                    "3. Compare common closed ports here against services you actually intend to publish.",
                    content_width - 1,
                )
            )
        elif selected_key and selected_key in self.analysis_cache:
            lines.append("AI Analysis")
            lines.append("")
            lines.extend(self.format_analysis_lines(self.analysis_cache[selected_key], content_width - 1))
        elif selected_key and selected_key in self.analysis_errors:
            lines.append("AI Warning")
            lines.append("")
            lines.extend(self.format_analysis_lines(self.analysis_errors[selected_key], content_width - 1))
        elif selected_key and self.analysis_loading_key == selected_key:
            lines.append("AI Analysis")
            lines.append("")
            lines.append("Generating a description for the selected port...")
        elif services and self.use_ai:
            lines.append("AI analysis will appear here for the selected open port.")
        elif services:
            lines.append("AI analysis is disabled. Press a to turn it back on.")
        elif self.results:
            lines.append("The scan completed, but no open services were detected.")
        else:
            lines.append("Run a scan to inspect open services and security guidance.")

        SECTION_LABELS = {
            "Overview:": self.color(COLOR_ACCENT) | curses.A_BOLD,
            "What is this:": self.color(COLOR_PANEL) | curses.A_BOLD,
            "Risks:": self.color(COLOR_DANGER) | curses.A_BOLD,
            "Actions:": self.color(COLOR_SUCCESS) | curses.A_BOLD,
        }

        for row, line in enumerate(lines[:content_height]):
            attr = curses.A_NORMAL
            if row == 0:
                attr = self.color(COLOR_ACCENT) | curses.A_BOLD
            elif line == "AI Analysis":
                attr = self.color(COLOR_AI) | curses.A_BOLD
            elif line == "AI Warning":
                attr = self.color(COLOR_WARNING) | curses.A_BOLD
            elif line == "Closed Port Note":
                attr = self.color(COLOR_WARNING) | curses.A_BOLD
            elif line.startswith("Risk:") and selected_service:
                attr = self.row_attr(selected_service)
            elif line.startswith("Security Score:"):
                if "Critical" in line or "Poor" in line:
                    attr = self.color(COLOR_DANGER) | curses.A_BOLD
                elif "Fair" in line:
                    attr = self.color(COLOR_WARNING) | curses.A_BOLD
                elif "Good" in line:
                    attr = self.color(COLOR_SUCCESS) | curses.A_BOLD
                else:
                    attr = self.color(COLOR_SUCCESS) | curses.A_BOLD
            elif line.startswith(("Host:", "Port:", "Service:", "Product:", "State:")):
                attr = self.color(COLOR_MUTED) | curses.A_BOLD
            elif selected_key and selected_key in self.analysis_errors:
                attr = self.color(COLOR_WARNING)
            elif selected_service and selected_service["state"] == "closed":
                attr = self.color(COLOR_MUTED)
            elif selected_key and selected_key in self.analysis_cache:
                attr = self.color(COLOR_MUTED)

            label_attr = None
            for label, lattr in SECTION_LABELS.items():
                if line.startswith(label):
                    label_attr = (label, lattr)
                    break

            if label_attr:
                label, lattr = label_attr
                stdscr.addnstr(content_y + row, content_x, label, content_width - 1, lattr)
                rest = line[len(label):]
                if rest:
                    rest_attr = self.color(COLOR_MUTED) if selected_key and selected_key in self.analysis_cache else curses.A_NORMAL
                    stdscr.addnstr(content_y + row, content_x + len(label), rest, content_width - 1 - len(label), rest_attr)
            else:
                stdscr.addnstr(content_y + row, content_x, line, content_width - 1, attr)


def launch_dashboard(initial_target=None, initial_ports=None, initial_use_ai=True, initial_scan_mode="tcp"):
    app = DashboardApp(initial_target, initial_ports, initial_use_ai, initial_scan_mode)
    return curses.wrapper(app.run)
