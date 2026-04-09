import argparse

import scanner


ALLOWED_RISKS = set(scanner.RISK_LEVELS.values()) | {"Unknown"}


def parse_expected_service(value):
    parts = value.split(":", 1)
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            "Expected PORT:SERVICE, for example 22:ssh"
        )

    port_text, service_name = parts
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid port in expectation: {port_text}"
        ) from exc

    service_name = service_name.strip().lower()
    if not service_name:
        raise argparse.ArgumentTypeError("Expected a non-empty service name")

    return port, service_name


def validate_results(results, expected_services):
    if not results:
        raise AssertionError("Scan returned no hosts.")

    hosts_up = [host for host in results if host["state"] == "up"]
    if not hosts_up:
        raise AssertionError("No hosts were reported as up.")

    open_services = scanner.collect_open_services(results)
    for service in open_services:
        if not isinstance(service["port"], int):
            raise AssertionError(f"Port is not an integer: {service}")
        if not service["service"]:
            raise AssertionError(f"Service name is missing: {service}")
        if service["risk"] not in ALLOWED_RISKS:
            raise AssertionError(f"Unexpected risk value: {service['risk']}")

    if expected_services:
        actual_services = {
            (service["port"], service["service"].lower())
            for service in open_services
        }
        missing_services = sorted(set(expected_services) - actual_services)
        if missing_services:
            missing_text = ", ".join(
                f"{port}:{service}" for port, service in missing_services
            )
            raise AssertionError(
                f"Expected localhost services were not found: {missing_text}"
            )

    return open_services


def main():
    parser = argparse.ArgumentParser(
        description="Validate the localhost scan path and optional AI analysis"
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=scanner.DEFAULT_PORT_RANGE,
        help=f"Port range to validate (default: {scanner.DEFAULT_PORT_RANGE})",
    )
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        type=parse_expected_service,
        help="Assert that localhost exposes PORT:SERVICE, for example 22:ssh",
    )
    parser.add_argument(
        "--check-ai",
        action="store_true",
        help="Require the Ollama-backed AI analysis step to succeed",
    )
    args = parser.parse_args()

    try:
        results = scanner.scan_network("localhost", args.ports)
        open_services = validate_results(results, args.expect)
        print(
            f"Validation passed: localhost responded with {len(open_services)} open service(s)."
        )

        if args.check_ai and open_services:
            analysis = scanner.get_ai_analysis(results)
            if not analysis.strip():
                raise AssertionError("AI analysis returned empty text.")
            print("AI validation passed: Ollama returned a non-empty analysis.")
        elif args.check_ai:
            print("AI validation skipped: localhost scan found no open services.")
    except (AssertionError, scanner.ScannerError, scanner.AIAnalysisError) as exc:
        print(f"Validation failed: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
