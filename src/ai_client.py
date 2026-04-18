import json
import logging
import re
import time
import urllib.error
import urllib.request


logger = logging.getLogger("scanner")

OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
AI_MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB

_CONTROL_CHAR_KEEP_NL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


class AIAnalysisError(Exception):
    """Raised when the AI analysis step fails."""


def sanitize_ai_text(text):
    if not text:
        return text
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHAR_KEEP_NL_RE.sub("", text)
    return text


def _format_product_name(service):
    product = service.get("product", "")
    if service.get("version"):
        product += f" {service['version']}"
    return product.strip() or "N/A"


def request_ai_response(prompt, announce_message=None):
    if announce_message:
        print(announce_message)

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        OLLAMA_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        ai_start = time.time()
        logger.debug("Sending AI request to %s", OLLAMA_API_URL)
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read(AI_MAX_RESPONSE_BYTES + 1)
            if len(raw) > AI_MAX_RESPONSE_BYTES:
                logger.warning("AI response exceeded %d bytes, truncated", AI_MAX_RESPONSE_BYTES)
                raw = raw[:AI_MAX_RESPONSE_BYTES]
            data = json.loads(raw)
        logger.debug("AI response received in %.1f seconds", time.time() - ai_start)
    except urllib.error.URLError as exc:
        logger.error("AI request failed (URL error): %s", exc)
        raise AIAnalysisError(
            "Could not reach Ollama at http://localhost:11434. Start Ollama or use --no-ai."
        ) from exc
    except json.JSONDecodeError as exc:
        logger.error("AI response was not valid JSON")
        raise AIAnalysisError("Ollama returned an invalid response.") from exc

    response = data.get("response", "").strip()
    if not response:
        logger.warning("AI returned an empty response")
        raise AIAnalysisError("Ollama returned an empty analysis.")
    return sanitize_ai_text(response)


def get_ai_analysis(results, announce=True):
    services_summary = []
    for host_info in results:
        for svc in host_info.get("services", []):
            services_summary.append(
                f"Port {svc['port']}: {svc['service']} "
                f"({_format_product_name(svc)}) - Risk: {svc['risk']}"
            )

    if not services_summary:
        return "No open services found to analyze."

    prompt = (
        "You are a cybersecurity expert. Analyze the following network scan results "
        "from a local network scan. For each open service:\n"
        "1. Identify what the port and service is — if the service name is empty, unknown, or "
        "tcpwrapped, use the port number to explain what commonly runs on that port\n"
        "2. Briefly explain what the service does\n"
        "3. Explain why it could be a security risk\n"
        "4. Suggest how to secure it\n\n"
        "Keep explanations clear and accessible for someone without deep security knowledge.\n\n"
        "Scan results:\n" + "\n".join(services_summary)
    )

    announce_message = None
    if announce:
        announce_message = "\n🤖 Generating AI security analysis (this may take a moment)..."
    return request_ai_response(prompt, announce_message)


def get_service_ai_analysis(service, announce=True):
    location = service.get("host", "unknown host")
    hostname = service.get("hostname") or "N/A"
    service_name = service["service"] or "unidentified"
    product = service.get("product", "") or "not detected"
    prompt = (
        "You are a cybersecurity expert. Analyze this single open network service and only this service.\n"
        "Return plain text only in exactly this format:\n"
        "Overview: <one short sentence about the detected service>\n\n"
        "What is this: <explain what this port/service is typically used for, what software commonly runs on it, "
        "and why it might be open on this machine — even if the service name is vague, empty, or wrapped>\n\n"
        "Risks:\n"
        "- <short risk>\n"
        "- <short risk>\n\n"
        "Actions:\n"
        "1. <short action>\n"
        "2. <short action>\n"
        "3. <short action>\n\n"
        "Rules:\n"
        "- No markdown formatting, code blocks, bold text, or headings other than Overview, What is this, Risks, Actions.\n"
        "- Add a blank line between each section (Overview, What is this, Risks, Actions).\n"
        "- If the service name is empty, unknown, or tcpwrapped, use the port number to infer what "
        "commonly runs there and explain that.\n"
        "- Focus only on the selected port.\n"
        "- Keep every line concise and easy to read in a terminal UI.\n\n"
        f"Host: {location} ({hostname})\n"
        f"Port: {service['port']}\n"
        f"Service: {service_name}\n"
        f"Product: {product}\n"
        f"Risk: {service['risk']}"
    )

    announce_message = None
    if announce:
        announce_message = (
            f"\n🤖 Generating AI security analysis for port {service['port']} "
            f"({service['service']})..."
        )
    return request_ai_response(prompt, announce_message)
