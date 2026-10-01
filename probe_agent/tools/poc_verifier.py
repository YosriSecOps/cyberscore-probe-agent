"""
CyberScore TN — Dynamic Proof-of-Concept (PoC) Verifier
Performs non-destructive, safe verification to confirm vulnerabilities without causing harm.
"""

import urllib.request
import urllib.parse
import urllib.error
import re
from typing import List, Dict, Any, Tuple
from probe_agent.models import VulnerabilityFinding


class PoCVerifier:
    """
    Executes controlled, non-destructive validation probes.
    """
    def __init__(self, target_host: str):
        self.target_host = target_host
        self.base_url = f"http://{target_host}"

    def verify_xss_reflection(self, endpoint: str = "/", param: str = "q") -> Tuple[bool, str]:
        """Test for unencoded input reflection (Potential XSS)."""
        safe_probe = "cs789<cs_test>"
        encoded_probe = urllib.parse.quote(safe_probe)
        url = f"{self.base_url}{endpoint}?{param}={encoded_probe}"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberScore-PoC-Tester/1.0"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if safe_probe in body:
                    return True, f"Probe unescaped in response: {url}"
        except Exception:
            pass
        return False, ""

    def verify_sql_error_disclosure(self, endpoint: str = "/", param: str = "id") -> Tuple[bool, str]:
        """Test for database syntax errors on benign quote injection."""
        sql_probe = "'"
        url = f"{self.base_url}{endpoint}?{param}={urllib.parse.quote(sql_probe)}"

        sql_patterns = [
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array",
            r"pg_query",
            r"SQLite3::",
            r"ORA-[0-9]{5}",
            r"ODBC SQL Server Driver",
        ]

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberScore-PoC-Tester/1.0"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                for pattern in sql_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        return True, f"Database error disclosed: '{match.group(0)}' at {url}"
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="ignore")
                for pattern in sql_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        return True, f"Database error disclosed in HTTP {e.code}: '{match.group(0)}'"
            except Exception:
                pass
        except Exception:
            pass
        return False, ""

    def verify_exposed_endpoint(self, endpoint: str) -> Tuple[bool, str]:
        """Verify if a sensitive endpoint exposes confidential data."""
        url = f"{self.base_url}{endpoint}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "CyberScore-PoC-Tester/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                if "phpinfo()" in body:
                    return True, f"phpinfo() actively exposed at {url}"
                if "ref: refs/heads/" in body:
                    return True, f"Git repository exposed at {url}"
                if "Index of /" in body:
                    return True, f"Directory indexing active at {url}"
                if resp.status == 200 and len(body) > 10:
                    return True, f"Sensitive resource HTTP 200 accessible: {url}"
        except Exception:
            pass
        return False, ""
