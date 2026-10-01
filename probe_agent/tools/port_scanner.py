"""
CyberScore TN — High-Speed Multi-Thread Port Scanner & Banner Grabber
Uses ThreadPoolExecutor with 150 concurrent workers for rapid socket probing.
Supports Top-100, Top-1000, and Full 65535 port scan profiles.
"""

import socket
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
from probe_agent.models import PortFinding

logger = logging.getLogger("probe_agent.port_scanner")

# ── Extended Service Map ────────────────────────────────────────────────────
SERVICE_MAP = {
    21: ("FTP", "critical", True),
    22: ("SSH", "low", False),
    23: ("Telnet", "critical", True),
    25: ("SMTP", "high", True),
    53: ("DNS", "low", False),
    80: ("HTTP", "info", False),
    110: ("POP3", "high", True),
    111: ("RPCBind", "high", True),
    135: ("MS-RPC", "high", True),
    139: ("NetBIOS", "high", True),
    143: ("IMAP", "high", True),
    443: ("HTTPS", "info", False),
    445: ("SMB", "critical", True),
    993: ("IMAPS", "low", False),
    995: ("POP3S", "low", False),
    1433: ("MSSQL", "critical", True),
    1521: ("Oracle-DB", "critical", True),
    3306: ("MySQL", "critical", True),
    3389: ("RDP", "critical", True),
    5432: ("PostgreSQL", "critical", True),
    6379: ("Redis", "critical", True),
    8000: ("HTTP-Alt", "medium", False),
    8008: ("HTTP-Alt-8008", "medium", False),
    8080: ("HTTP-Proxy", "medium", False),
    8081: ("HTTP-Admin", "high", True),
    8443: ("HTTPS-Alt", "low", False),
    8888: ("HTTP-Admin", "high", True),
    9000: ("Portainer/Sonar", "medium", False),
    9443: ("HTTPS-Admin", "medium", False),
    9929: ("Nping-Echo", "medium", False),
    10000: ("Webmin", "high", True),
    27017: ("MongoDB", "critical", True),
    31337: ("Elite/tcpwrapped", "high", True),
}

# ── Port Scan Profiles ─────────────────────────────────────────────────────

# Nmap Top 1000 ports (curated subset covering the most common services)
TOP_1000_PORTS = sorted(set([
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
    37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
    100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
    163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
    311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
    464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
    667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
    777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
    903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
    1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027,
    1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
    1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
    1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
    1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071,
    1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
    1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093,
    1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
    1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122,
    1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147,
    1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174,
    1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216,
    1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272,
    1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334,
    1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
    1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666,
    1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761,
    1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
    1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000,
    2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
    2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042,
    2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103,
    2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
    2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301,
    2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500,
    2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701,
    2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909,
    2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007,
    3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211,
    3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323,
    3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390,
    3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690,
    3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828,
    3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945,
    3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006,
    4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443,
    4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
    5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054,
    5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214,
    5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,
    5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633,
    5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815,
    5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904,
    5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960,
    5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002,
    6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565,
    6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699,
    6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002,
    7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402,
    7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800,
    7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008,
    8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082,
    8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100,
    8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292,
    8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652,
    8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003,
    9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099,
    9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
    9418, 9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
    9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944,
    9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
    10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617,
    10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174,
    12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442,
    15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
    16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
    19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031,
    20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735,
    26214, 27000, 27017, 27352, 27353, 27355, 27356, 27715, 28201, 30000,
    30718, 30951, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
    32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784,
    32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911,
    41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153,
    49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006,
    50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848,
    52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294,
    57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680,
    65000, 65129, 65389,
]))

# ── Core Thread-Based Scanner ──────────────────────────────────────────────

# Stability-tuned constants:
# - SCAN_TIMEOUT raised to 2.5s  → prevents false-negatives on high-latency public sites
# - BANNER_TIMEOUT raised to 2.0s → allows remote servers time to respond
# - MAX_WORKERS reduced to 40    → avoids triggering remote rate-limiting / SYN-flood
#   protection that causes random port closures on repeated scans of public sites
SCAN_TIMEOUT = 2.5   # seconds per socket connect (tuned for public internet targets)
MAX_WORKERS = 40     # conservative concurrency — stable across CDN/firewall-protected sites
BANNER_TIMEOUT = 2.0

# Maximum retry attempts for ports in SERVICE_MAP (important known ports)
MAX_SERVICE_RETRIES = 3
RETRY_BACKOFF_S = 0.3  # Exponential back-off base: 0.3s, 0.6s between retries


def _probe_port(ip: str, host: str, port: int) -> Tuple[int, bool, str]:
    """
    Probe a single port using a blocking socket with pre-resolved IP.
    Returns (port, is_open, banner). Designed to run inside a ThreadPoolExecutor.

    For ports in SERVICE_MAP (critical/known services), retries up to MAX_SERVICE_RETRIES
    times with exponential back-off to absorb transient packet loss or rate-limiting.
    """
    max_attempts = MAX_SERVICE_RETRIES if port in SERVICE_MAP else 1

    for attempt in range(max_attempts):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT)
            sock.connect((ip, port))

            # Port is open — grab banner
            banner = ""
            try:
                if port in (80, 8080, 8000, 8008, 8081, 8443):
                    # Use a neutral browser-like UA to avoid WAF/CDN filtering
                    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; CyberScore/2.0)\r\nConnection: close\r\n\r\n"
                    sock.sendall(req.encode("ascii", errors="ignore"))
                sock.settimeout(BANNER_TIMEOUT)
                data = sock.recv(512)
                # Decode cleanly into printable ASCII
                banner = data.decode("ascii", errors="ignore").strip().replace("\r", "").replace("\n", " ")
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            return (port, True, banner)

        except (socket.timeout, TimeoutError):
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            if attempt < max_attempts - 1:
                import time
                time.sleep(RETRY_BACKOFF_S * (attempt + 1))  # 0.3s, 0.6s back-off
                continue
            return (port, False, "")

        except ConnectionRefusedError:
            # Definitively closed — no retry needed, short-circuit immediately
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            return (port, False, "")

        except Exception:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            return (port, False, "")

    return (port, False, "")


def scan_ports_threaded(host: str, ports: Optional[List[int]] = None) -> List[PortFinding]:
    """
    High-speed multi-threaded port scan using ThreadPoolExecutor.
    Pre-resolves host IP to eliminate concurrent DNS contention.
    Prioritizes known critical ports first to ensure service detection.
    """
    if ports is None:
        ports = TOP_1000_PORTS

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        logger.warning(f"Port scanner failed to resolve IP for {host}: {e}")
        ip = host

    logger.info(f"[*] Starting multi-threaded scan on {host} ({ip}) — {len(ports)} ports, {MAX_WORKERS} workers...")
    findings: List[PortFinding] = []

    # Prioritize key services first so they complete before extended range
    priority_ports = [p for p in ports if p in SERVICE_MAP]
    standard_ports = [p for p in ports if p not in SERVICE_MAP]
    ordered_ports = priority_ports + standard_ports

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_probe_port, ip, host, port): port for port in ordered_ports}

        for future in as_completed(futures):
            try:
                port, is_open, banner = future.result()
                if is_open:
                    srv_info = SERVICE_MAP.get(port, ("Unknown", "medium", False))
                    findings.append(PortFinding(
                        port=port,
                        service=srv_info[0],
                        state="open",
                        banner=banner[:120],
                        is_risky=srv_info[2],
                        severity=srv_info[1],
                    ))
                    clean_banner = banner[:60].encode("ascii", errors="ignore").decode("ascii")
                    logger.info(f"  [+] Port {port}/TCP open ({srv_info[0]}) {f'Banner: {clean_banner}' if clean_banner else ''}")
            except Exception as e:
                logger.debug(f"  [-] Error scanning port {futures[future]}: {e}")

    # Sort findings by port number for clean, deterministic output
    findings.sort(key=lambda f: f.port)
    logger.info(f"[*] Scan complete: {len(findings)} open ports discovered out of {len(ports)} tested")
    return findings


async def scan_target_ports(host: str, ports: Optional[List[int]] = None) -> List[PortFinding]:
    """
    Async wrapper for the threaded scanner.
    Maintains backward-compatibility with the existing async recon_agent call.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, scan_ports_threaded, host, ports)

