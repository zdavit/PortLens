import curses
import textwrap
import threading
import time
from queue import Empty, Queue

import scanner


SPINNER_FRAMES = ["|", "/", "-", "\\"]


class DashboardApp:
    def __init__(self, initial_target=None, initial_ports=None, initial_use_ai=True):
        self.target = initial_target or self._safe_default_target()
        self.ports = initial_ports or scanner.DEFAULT_PORT_RANGE
        self.use_ai = initial_use_ai
        self.status_message = "Ready. Press r to scan."
        self.results = []
        self.analysis = ""
        self.ai_warning = ""
        self.error_message = ""
        self.selected_index = 0
        self.scroll_offset = 0
        self.running = False
        self.spinner_index = 0
        self.worker = None
        self.events = Queue()

    def _safe_default_target(self):
        try:
            return scanner.get_default_target()
        except scanner.ScannerError:
            return "localhost"

    def flatten_services(self):
        flattened = []
        for host_info in self.results:
            hostname = host_info["hostname"] or "N/A"
            for service in host_info["services"]:
                flattened.append(
                    {
                        "host": host_info["host"],
                        "hostname": hostname,
                        "port": service["port"],
                        "service": service["service"],
                        "product": scanner.format_product_name(service),
                        "risk": service["risk"],
                    }
                )
        return flattened

    def start_scan(self):
        if self.running:
            return

        self.running = True
        self.spinner_index = 0
        self.results = []
        self.analysis = ""
        self.ai_warning = ""
        self.error_message = ""
        self.selected_index = 0
        self.scroll_offset = 0
        self.status_message = f"Scanning {self.target} on ports {self.ports}..."
        self.worker = threading.Thread(target=self._scan_worker, daemon=True)
        self.worker.start()

    def _scan_worker(self):
        try:
            self.events.put(("status", f"Scanning {self.target} on ports {self.ports}..."))
            results = scanner.scan_network(self.target, self.ports, announce=False)
            self.events.put(("results", results))

            services = scanner.collect_open_services(results)
            if self.use_ai and services:
                self.events.put(("status", "Generating AI security analysis..."))
                try:
                    analysis = scanner.get_ai_analysis(results, announce=False)
                except scanner.AIAnalysisError as exc:
                    self.events.put(("ai_warning", str(exc)))
                else:
                    self.events.put(("analysis", analysis))

            self.events.put(("done", None))
        except scanner.ScannerError as exc:
            self.events.put(("error", str(exc)))
            self.events.put(("done", None))

    def process_events(self):
        changed = False
        while True:
            try:
                event, payload = self.events.get_nowait()
            except Empty:
                break

            changed = True
            if event == "status":
                self.status_message = payload
            elif event == "results":
                self.results = payload
                self.selected_index = 0
                self.scroll_offset = 0
                total_services = len(self.flatten_services())
                self.status_message = (
                    f"Scan finished: {len(payload)} host(s), {total_services} open service(s)."
                )
            elif event == "analysis":
                self.analysis = payload
            elif event == "ai_warning":
                self.ai_warning = payload
            elif event == "error":
                self.error_message = payload
                self.status_message = "Scan failed."
            elif event == "done":
                self.running = False
                if self.ai_warning and not self.error_message:
                    self.status_message = "Scan finished with an AI warning."
        return changed

    def move_selection(self, delta):
        services = self.flatten_services()
        if not services:
            self.selected_index = 0
            self.scroll_offset = 0
            return

        self.selected_index = max(0, min(self.selected_index + delta, len(services) - 1))

    def cycle_spinner(self):
        if self.running:
            self.spinner_index = (self.spinner_index + 1) % len(SPINNER_FRAMES)

    def run(self, stdscr):
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)
        stdscr.nodelay(True)

        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
            curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE)

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
            if key in (ord("r"), ord("R")):
                self.start_scan()
            elif key in (ord("a"), ord("A")) and not self.running:
                self.use_ai = not self.use_ai
                self.ai_warning = ""
                state = "enabled" if self.use_ai else "disabled"
                self.status_message = f"AI analysis {state}."
            elif key in (ord("t"), ord("T")) and not self.running:
                updated = self.prompt_input(stdscr, "Target", self.target)
                if updated is not None:
                    self.target = updated.strip() or self.target
                    self.status_message = f"Target set to {self.target}."
            elif key in (ord("p"), ord("P")) and not self.running:
                updated = self.prompt_input(stdscr, "Ports", self.ports)
                if updated is not None:
                    self.ports = updated.strip() or self.ports
                    self.status_message = f"Ports set to {self.ports}."
            elif key in (ord("d"), ord("D")) and not self.running:
                try:
                    self.target = scanner.get_default_target()
                except scanner.ScannerError as exc:
                    self.error_message = str(exc)
                    self.status_message = "Could not detect a default subnet."
                else:
                    self.status_message = f"Target reset to {self.target}."
            elif key in (curses.KEY_UP, ord("k")):
                self.move_selection(-1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.move_selection(1)

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
        window.addnstr(0, 2, title, box_width - 4)
        window.addnstr(2, 2, f"Enter {label.lower()} and press Enter.", box_width - 4)
        window.addnstr(4, 2, current_value, box_width - 4)
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
        elif self.error_message:
            scan_state = "ERROR"
        stdscr.attron(curses.A_BOLD)
        stdscr.addnstr(0, 2, header, width - 4)
        stdscr.attroff(curses.A_BOLD)
        stdscr.addnstr(0, max(2, width - len(scan_state) - 3), scan_state, len(scan_state))

        top_height = 7
        content_top = top_height + 1
        body_height = height - content_top - 2
        left_width = max(40, width // 2)
        right_width = width - left_width - 1

        self.draw_box(stdscr, 1, 0, top_height, width, "Controls")
        controls = [
            f"Target: {self.target}",
            f"Ports: {self.ports}",
            f"AI Analysis: {'ON' if self.use_ai else 'OFF'}",
            "Keys: r scan  t edit target  p edit ports  a toggle ai  d default target  j/k move  q quit",
            f"Status: {self.status_message}",
        ]
        for index, line in enumerate(controls, start=1):
            stdscr.addnstr(1 + index, 2, line, width - 4)

        self.draw_box(stdscr, content_top, 0, body_height, left_width, "Open Services")
        self.draw_services_pane(stdscr, content_top, 0, body_height, left_width)

        self.draw_box(stdscr, content_top, left_width, body_height, right_width + 1, "Details")
        self.draw_detail_pane(stdscr, content_top, left_width, body_height, right_width + 1)

        footer = "Interactive mode keeps the UI live while scans run in the background."
        stdscr.addnstr(height - 1, 2, footer, width - 4)
        stdscr.refresh()

    def draw_box(self, stdscr, start_y, start_x, box_height, box_width, title):
        if box_height < 3 or box_width < 10:
            return
        max_y, max_x = stdscr.getmaxyx()
        bottom = min(max_y - 1, start_y + box_height - 1)
        right = min(max_x - 1, start_x + box_width - 1)
        stdscr.hline(start_y, start_x + 1, curses.ACS_HLINE, max(1, right - start_x - 1))
        stdscr.hline(bottom, start_x + 1, curses.ACS_HLINE, max(1, right - start_x - 1))
        stdscr.vline(start_y + 1, start_x, curses.ACS_VLINE, max(1, bottom - start_y - 1))
        stdscr.vline(start_y + 1, right, curses.ACS_VLINE, max(1, bottom - start_y - 1))
        stdscr.addch(start_y, start_x, curses.ACS_ULCORNER)
        stdscr.addch(start_y, right, curses.ACS_URCORNER)
        stdscr.addch(bottom, start_x, curses.ACS_LLCORNER)
        stdscr.addch(bottom, right, curses.ACS_LRCORNER)
        stdscr.addnstr(start_y, start_x + 2, f" {title} ", max(1, right - start_x - 3), curses.A_BOLD)

    def draw_services_pane(self, stdscr, start_y, start_x, box_height, box_width):
        services = self.flatten_services()
        view_height = box_height - 3
        inner_width = box_width - 2
        if not services:
            empty_message = self.error_message or "No scan results yet. Press r to run a scan."
            stdscr.addnstr(start_y + 2, start_x + 2, empty_message, inner_width - 2)
            return

        max_visible = max(1, view_height - 1)
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + max_visible:
            self.scroll_offset = self.selected_index - max_visible + 1

        header = "Port  Service       Risk     Host"
        stdscr.addnstr(start_y + 1, start_x + 2, header, inner_width - 2, curses.A_BOLD)
        visible_services = services[self.scroll_offset : self.scroll_offset + max_visible]
        for row, service in enumerate(visible_services, start=0):
            actual_index = self.scroll_offset + row
            line = (
                f"{service['port']:<5} "
                f"{service['service'][:12]:<12} "
                f"{service['risk'][:8]:<8} "
                f"{service['host'][:inner_width - 32]}"
            )
            attrs = curses.A_REVERSE if actual_index == self.selected_index else curses.A_NORMAL
            stdscr.addnstr(start_y + 2 + row, start_x + 2, line, inner_width - 2, attrs)

    def draw_detail_pane(self, stdscr, start_y, start_x, box_height, box_width):
        services = self.flatten_services()
        content_y = start_y + 1
        content_x = start_x + 2
        content_width = box_width - 3
        content_height = box_height - 2
        lines = []

        if services:
            service = services[self.selected_index]
            lines.extend(
                [
                    f"Host: {service['host']} ({service['hostname']})",
                    f"Port: {service['port']}",
                    f"Service: {service['service']}",
                    f"Product: {service['product']}",
                    f"Risk: {service['risk']}",
                    "",
                ]
            )

        if self.analysis:
            lines.append("AI Analysis")
            lines.append("")
            lines.extend(textwrap.wrap(self.analysis, width=max(20, content_width - 1)))
        elif self.ai_warning:
            lines.append("AI Warning")
            lines.append("")
            lines.extend(textwrap.wrap(self.ai_warning, width=max(20, content_width - 1)))
        elif services and self.use_ai:
            lines.append("AI analysis will appear here after the scan finishes.")
        elif services:
            lines.append("AI analysis is disabled. Press a to turn it back on.")
        elif self.results:
            lines.append("The scan completed, but no open services were detected.")
        else:
            lines.append("Run a scan to inspect open services and security guidance.")

        for row, line in enumerate(lines[:content_height]):
            attr = curses.A_BOLD if row == 0 or line == "AI Analysis" or line == "AI Warning" else curses.A_NORMAL
            stdscr.addnstr(content_y + row, content_x, line, content_width - 1, attr)


def launch_dashboard(initial_target=None, initial_ports=None, initial_use_ai=True):
    app = DashboardApp(initial_target, initial_ports, initial_use_ai)
    return curses.wrapper(app.run)
