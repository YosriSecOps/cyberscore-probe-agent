"""
CyberScore TN — Network OS Fingerprinter & Distance Telemetry
Determines the operating system family, network hop distance, and latency using IP TTL and banner correlation.
"""

import subprocess
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger("probe_agent.os_fingerprinter")


def detect_os_fingerprint(target_host: str, target_ip: str, banners: List[str]) -> Dict[str, Any]:
    """
    Perform passive and active TCP/IP TTL fingerprinting to identify the target OS and hop distance.
    """
    result: Dict[str, Any] = {
        "os_family": "Unknown",
        "os_detailed": "Unknown OS",
        "ttl_received": None,
        "hops_distance": None,
        "rtt_ms": None,
        "confidence": 50,
        "method": "Heuristic Estimation"
    }

    # 1. Probe TTL and Latency via ICMP / Ping probe
    ttl_val = None
    rtt_val = None
    try:
        # Windows ping: ping -n 1 -w 1500 target
        cmd = ["ping", "-n", "1", "-w", "1800", target_host]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=2.5)
        
        # Regex for TTL
        ttl_match = re.search(r'TTL=(\d+)', out, re.IGNORECASE)
        if ttl_match:
            ttl_val = int(ttl_match.group(1))
            result["ttl_received"] = ttl_val

        # Regex for RTT time
        rtt_match = re.search(r'time[=<](\d+)ms', out, re.IGNORECASE)
        if rtt_match:
            rtt_val = float(rtt_match.group(1))
            result["rtt_ms"] = rtt_val
    except Exception as e:
        logger.debug(f"Ping TTL check failed or timed out: {e}")

    # 2. Derive OS Family from TTL
    os_family = "Unknown"
    hops = None
    if ttl_val is not None:
        if ttl_val <= 64:
            os_family = "Linux"
            hops = 64 - ttl_val
        elif ttl_val <= 128:
            os_family = "Windows"
            hops = 128 - ttl_val
        else:
            os_family = "Solaris/Cisco/BSD"
            hops = 255 - ttl_val
        
        result["os_family"] = os_family
        result["hops_distance"] = hops
        result["method"] = "IP Packet TTL Fingerprint"
        result["confidence"] = 75

    # 3. Correlate with Banners (Banner Grabbing Context)
    combined_banners = " ".join(banners).lower()
    
    if "ubuntu" in combined_banners:
        result["os_family"] = "Linux"
        # Extract version if present, e.g., Ubuntu-2ubuntu2.13 -> Ubuntu 14.04 Trusty
        if "ubuntu2.13" in combined_banners or "2.4.7" in combined_banners:
            result["os_detailed"] = "Ubuntu Linux 14.04 LTS (Trusty Tahr / Kernel 3.13)"
            result["confidence"] = 95
        else:
            result["os_detailed"] = "Ubuntu Linux"
            result["confidence"] = 90
    elif "debian" in combined_banners:
        result["os_family"] = "Linux"
        result["os_detailed"] = "Debian GNU/Linux"
        result["confidence"] = 90
    elif "centos" in combined_banners:
        result["os_family"] = "Linux"
        result["os_detailed"] = "CentOS Linux"
        result["confidence"] = 90
    elif "red hat" in combined_banners or "rhel" in combined_banners:
        result["os_family"] = "Linux"
        result["os_detailed"] = "Red Hat Enterprise Linux (RHEL)"
        result["confidence"] = 90
    elif "microsoft-iis" in combined_banners or "windows" in combined_banners:
        result["os_family"] = "Windows"
        if "iis/10.0" in combined_banners:
            result["os_detailed"] = "Microsoft Windows Server 2016 / 2019 / 2022"
        elif "iis/8.5" in combined_banners:
            result["os_detailed"] = "Microsoft Windows Server 2012 R2"
        elif "iis/7.5" in combined_banners:
            result["os_detailed"] = "Microsoft Windows Server 2008 R2"
        else:
            result["os_detailed"] = "Microsoft Windows Server"
        result["confidence"] = 90
    elif os_family == "Linux":
        result["os_detailed"] = "Linux Kernel 3.x / 4.x / 5.x"
    elif os_family == "Windows":
        result["os_detailed"] = "Microsoft Windows NT Architecture"

    if result["hops_distance"] is not None and result["confidence"] >= 80:
        result["method"] = "TCP/IP TTL + Application Banner Multi-Layer Fingerprint"

    logger.info(f"OS Fingerprint for {target_host}: {result['os_detailed']} ({result['os_family']}), TTL={result['ttl_received']}, Hops={result['hops_distance']}")
    return result
