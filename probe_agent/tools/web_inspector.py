"""
CyberScore TN — Web Stack & Security Header Inspector
Inspects HTTP/HTTPS headers, TLS certs, and technology footprints.
"""

import ssl
import socket
import urllib.request
import urllib.error
import http.client
from typing import Dict, Any, List, Tuple
from probe_agent.config import HTTP_TIMEOUT, SENSITIVE_ENDPOINTS


def inspect_web_target(target_host: str) -> Dict[str, Any]:
    """
    Perform deep web inspection over HTTP and HTTPS.
    """
    result: Dict[str, Any] = {
        "headers": {},
        "technologies": [],
        "ssl_info": {},
        "discovered_endpoints": [],
        "cookies": [],
        "missing_headers": [],
    }

    # Create permissive SSL context for scanning (does not crash on self-signed certs)
    unverified_ctx = ssl.create_default_context()
    unverified_ctx.check_hostname = False
    unverified_ctx.verify_mode = ssl.CERT_NONE

    # 1. Inspect TLS/SSL Certificate on port 443
    try:
        with socket.create_connection((target_host, 443), timeout=HTTP_TIMEOUT) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                result["ssl_info"] = {
                    "valid": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "expires": cert.get("notAfter", "") if cert else "",
                }
    except Exception as e:
        result["ssl_info"] = {"valid": False, "error": str(e)[:100]}

    # 2. Inspect HTTP Headers (try HTTPS first with permissive context, fallback to HTTP)
    scheme = "https" if result["ssl_info"].get("valid") else "http"
    base_url = f"{scheme}://{target_host}"

    headers_dict = {}
    urls_to_test = [f"https://{target_host}", f"http://{target_host}"] if result["ssl_info"].get("valid") else [f"http://{target_host}", f"https://{target_host}"]
    for test_url in urls_to_test:
        try:
            req = urllib.request.Request(
                test_url,
                headers={"User-Agent": "CyberScore-Security-Auditor/1.0", "Accept": "*/*"}
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=unverified_ctx) as resp:
                for k, v in resp.getheaders():
                    headers_dict[k.lower()] = v
            if headers_dict:
                base_url = test_url
                break
        except urllib.error.HTTPError as e:
            for k, v in e.headers.items():
                headers_dict[k.lower()] = v
            base_url = test_url
            break
        except Exception:
            continue

    result["headers"] = headers_dict

    # 3. Detect Technologies
    server_header = headers_dict.get("server", "")
    powered_by = headers_dict.get("x-powered-by", "")
    techs = []
    if server_header:
        techs.append(f"Server: {server_header}")
    if powered_by:
        techs.append(f"Framework: {powered_by}")

    # Check for missing crucial security headers
    critical_security_headers = [
        ("strict-transport-security", "HSTS (Protection contre le downgrade SSL/TLS)", "high"),
        ("content-security-policy", "CSP (Prévention des injections XSS)", "high"),
        ("x-frame-options", "Anti-Clickjacking", "medium"),
        ("x-content-type-options", "MIME Sniffing Prevention", "medium"),
        ("referrer-policy", "Protection des fuites de referrers", "low"),
        ("permissions-policy", "Restriction des APIs du navigateur", "low"),
    ]

    missing = []
    for h_name, h_desc, h_sev in critical_security_headers:
        if h_name not in headers_dict:
            missing.append({"header": h_name, "desc": h_desc, "severity": h_sev})

    result["missing_headers"] = missing
    result["technologies"] = techs

    # 4. Probe Sensitive Endpoints (Non-destructive HEAD/GET) & Page Title
    discovered = []
    page_title = ""
    for ep in SENSITIVE_ENDPOINTS:
        try:
            ep_url = f"{base_url}{ep}"
            req = urllib.request.Request(ep_url, headers={"User-Agent": "CyberScore-Security-Auditor/1.0"})
            with urllib.request.urlopen(req, timeout=2.5, context=unverified_ctx) as resp:
                if resp.status in (200, 301, 302, 403):
                    discovered.append(f"{ep} ({resp.status})")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                discovered.append(f"{ep} ({e.code} Protected)")
        except Exception:
            continue

    # Extract Page Title from base_url
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": "CyberScore-Security-Auditor/1.0"})
        with urllib.request.urlopen(req, timeout=3.0, context=unverified_ctx) as resp:
            content_sample = resp.read(8192).decode("utf-8", errors="ignore")
            import re
            m = re.search(r'<title[^>]*>(.*?)</title>', content_sample, re.IGNORECASE | re.DOTALL)
            if m:
                page_title = m.group(1).strip().replace("\r", "").replace("\n", " ")
    except Exception:
        pass

    # 5. Probe Allowed HTTP Methods via OPTIONS
    allowed_methods = []
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": "CyberScore-Security-Auditor/1.0"}, method="OPTIONS")
        with urllib.request.urlopen(req, timeout=2.5, context=unverified_ctx) as resp:
            allow_header = resp.getheader("Allow") or resp.getheader("allow")
            if allow_header:
                allowed_methods = [m.strip() for m in allow_header.split(",") if m.strip()]
    except Exception:
        pass

    # 6. IPv6 Resolution (Dual-Stack)
    ipv6_address = None
    try:
        # First attempt via local socket
        addr_info = socket.getaddrinfo(target_host, None, socket.AF_INET6)
        if addr_info:
            ipv6_address = addr_info[0][4][0]
    except Exception:
        # Fallback via secure DNS over HTTPS (DoH)
        try:
            doh_url = f"https://dns.google/resolve?name={target_host}&type=AAAA"
            req = urllib.request.Request(doh_url, headers={"User-Agent": "CyberScore-Security-Auditor/1.0"})
            with urllib.request.urlopen(req, timeout=2.5, context=unverified_ctx) as resp:
                import json
                doh_data = json.loads(resp.read().decode("utf-8"))
                for ans in doh_data.get("Answer", []):
                    if ans.get("type") == 28 and ans.get("data"):  # Type 28 = AAAA
                        ipv6_address = ans["data"]
                        break
        except Exception:
            pass

    result["discovered_endpoints"] = discovered
    result["ipv6_address"] = ipv6_address
    result["web_surface"] = {
        "page_title": page_title,
        "http_methods": allowed_methods,
        "has_robots_txt": any("/robots.txt" in ep for ep in discovered)
    }
    return result

