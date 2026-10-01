"""
CyberScore TN — Agent 1: Reconnaissance Agent (Advanced)
Discovers IP/IPv6 addresses, scans Top 1000 ports with multi-threaded engine,
performs OS fingerprinting, software obsolescence analysis, and web surface inspection.
"""

import socket
import logging
from probe_agent.models import AuditState
from probe_agent.tools.port_scanner import scan_target_ports
from probe_agent.tools.web_inspector import inspect_web_target
from probe_agent.tools.os_fingerprinter import detect_os_fingerprint
from probe_agent.tools.obsolescence_checker import check_software_obsolescence

logger = logging.getLogger("probe_agent.recon")


class ReconAgent:
    """
    Agent 1: Executes network and application fingerprinting.
    Orchestrates: Port Scan → Web Inspection → OS Fingerprint → Obsolescence Analysis
    """
    async def run(self, state: AuditState) -> AuditState:
        logger.info(f"[*] [AGENT 1: RECONNAISSANCE] Starting advanced audit on {state.target_host}...")
        state.status = "recon"

        # ── 1. Resolve IPv4 Address ────────────────────────────────────
        try:
            state.ip_address = socket.gethostbyname(state.target_host)
            logger.info(f"  -> Target IP resolved: {state.ip_address}")
        except Exception as e:
            logger.error(f"  -> DNS resolution failed: {e}")
            state.ip_address = "Unresolved"
            raise ConnectionError(f"Résolution DNS impossible pour '{state.target_host}'. Le domaine est inexistant ou inactif.")

        # ── 2. High-Speed Multi-Thread Port & Service Discovery ────────
        state.open_ports = await scan_target_ports(state.target_host)
        logger.info(f"  -> Discovered {len(state.open_ports)} open TCP ports (Top 1000 multi-thread scan)")

        # ── 3. Web Stack & Security Headers Inspection ─────────────────
        web_data = inspect_web_target(state.target_host)
        state.headers = web_data.get("headers", {})
        state.technologies = web_data.get("technologies", [])
        state.ssl_info = web_data.get("ssl_info", {})
        state.discovered_endpoints = web_data.get("discovered_endpoints", [])

        # Store missing headers as initial findings context
        for mh in web_data.get("missing_headers", []):
            state.technologies.append(f"Missing Security Header: {mh['header']}")

        # ── 4. IPv6 Dual-Stack Resolution ──────────────────────────────
        ipv6 = web_data.get("ipv6_address")
        if ipv6:
            state.ipv6_address = ipv6
            logger.info(f"  -> IPv6 dual-stack address discovered: {ipv6}")
        else:
            logger.info(f"  -> No IPv6 (AAAA) record found for {state.target_host}")

        # ── 5. Web Surface Metadata ────────────────────────────────────
        web_surface = web_data.get("web_surface", {})
        state.web_surface = web_surface
        if web_surface.get("page_title"):
            logger.info(f"  -> Page title extracted: '{web_surface['page_title']}'")
        if web_surface.get("http_methods"):
            logger.info(f"  -> Allowed HTTP methods: {web_surface['http_methods']}")

        # ── 6. OS Fingerprinting (TTL + Banner Correlation) ────────────
        banners = [p.banner for p in state.open_ports if p.banner]
        if state.headers.get("server"):
            banners.append(f"Server: {state.headers['server']}")
        os_result = detect_os_fingerprint(state.target_host, state.ip_address, banners)
        state.os_detection = os_result
        logger.info(f"  -> OS Fingerprint: {os_result['os_detailed']} (TTL={os_result['ttl_received']}, Hops={os_result['hops_distance']}, Confidence={os_result['confidence']}%)")

        # ── 7. Software Obsolescence & EOL Analysis ────────────────────
        all_tech_strings = state.technologies + banners + [os_result.get("os_detailed", "")]
        obsolescence_findings = check_software_obsolescence(banners, all_tech_strings)
        state.software_obsolescence = obsolescence_findings
        if obsolescence_findings:
            for obs in obsolescence_findings:
                logger.warning(f"  -> ⚠ OBSOLETE: {obs['component']} ({obs['detected_string']}) — {obs['age_years']} years old, Status: {obs['eol_status']}")
        else:
            logger.info(f"  -> No critical software obsolescence detected")

        logger.info(f"  -> Detected technologies: {state.technologies}")
        logger.info(f"  -> Discovered endpoints: {state.discovered_endpoints}")
        return state
