"""
CyberScore TN — Software Obsolescence & End-Of-Life (EOL) Analyzer
Evaluates the release age of detected software components and identifies historical vulnerability exposure.
"""

import re
import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger("probe_agent.obsolescence")

CURRENT_YEAR = datetime.utcnow().year

# Knowledge base of historical releases, release years, and EOL status
OBSOLESCENCE_KB = [
    {
        "pattern": r"apache/2\.4\.(0|[1-9]|1[0-9]|2[0-9])\b",
        "component": "Apache HTTP Server",
        "release_year": 2013,
        "eol_status": "END_OF_LIFE",
        "cve_count": 28,
        "sample_cves": ["CVE-2014-0226", "CVE-2014-0118", "CVE-2017-9798", "CVE-2021-41773"],
        "recommendation": "Mettre à jour Apache HTTPD vers la version 2.4.58 ou supérieure."
    },
    {
        "pattern": r"apache/2\.2\.",
        "component": "Apache HTTP Server 2.2.x",
        "release_year": 2005,
        "eol_status": "END_OF_LIFE_OBSOLETE",
        "cve_count": 45,
        "sample_cves": ["CVE-2017-9798", "CVE-2011-3192", "CVE-2012-0053"],
        "recommendation": "Version Apache 2.2 obsolète depuis 2017. Migration impérative vers Apache 2.4.x."
    },
    {
        "pattern": r"openssh[_-]6\.[0-9]",
        "component": "OpenSSH 6.x",
        "release_year": 2014,
        "eol_status": "END_OF_LIFE",
        "cve_count": 14,
        "sample_cves": ["CVE-2016-0777", "CVE-2015-5600", "CVE-2016-10009"],
        "recommendation": "Mettre à jour OpenSSH vers une version supportée (9.x) et désactiver les algorithmes obsolètes."
    },
    {
        "pattern": r"openssh[_-][1-5]\.",
        "component": "OpenSSH Legacy (<= 5.x)",
        "release_year": 2010,
        "eol_status": "CRITICAL_OBSOLETE",
        "cve_count": 30,
        "sample_cves": ["CVE-2008-5161", "CVE-2006-5051"],
        "recommendation": "Mise à niveau d'urgence immédiate vers OpenSSH 9.x."
    },
    {
        "pattern": r"php/(5\.[0-9]|7\.[0-3])",
        "component": "PHP Runtime (Legacy)",
        "release_year": 2015,
        "eol_status": "END_OF_LIFE",
        "cve_count": 60,
        "sample_cves": ["CVE-2019-11043", "CVE-2018-19518"],
        "recommendation": "Version PHP non supportée depuis plus de 4 ans. Migrer vers PHP 8.2 ou 8.3."
    },
    {
        "pattern": r"nginx/1\.(0|2|4|6|8)\.",
        "component": "Nginx Web Server (Legacy)",
        "release_year": 2014,
        "eol_status": "END_OF_LIFE",
        "cve_count": 15,
        "sample_cves": ["CVE-2013-4547", "CVE-2017-7529"],
        "recommendation": "Mettre à jour Nginx vers la branche stable 1.24+ ou mainline."
    },
    {
        "pattern": r"ubuntu[ -]?14\.04",
        "component": "Ubuntu Linux 14.04 (Trusty Tahr)",
        "release_year": 2014,
        "eol_status": "END_OF_LIFE",
        "cve_count": 120,
        "sample_cves": ["Dirty COW (CVE-2016-5195)", "Ghost (CVE-2015-0235)"],
        "recommendation": "Le système d'exploitation n'est plus maintenu depuis 2019. Effectuer une migration vers Ubuntu 22.04 LTS ou 24.04 LTS."
    }
]


def check_software_obsolescence(banners: List[str], tech_stack: List[str]) -> List[Dict[str, Any]]:
    """
    Scan banners and technology strings against the obsolescence knowledge base.
    """
    findings: List[Dict[str, Any]] = []
    seen_components = set()

    full_text = " ".join(banners + tech_stack)

    for entry in OBSOLESCENCE_KB:
        match = re.search(entry["pattern"], full_text, re.IGNORECASE)
        if match:
            matched_str = match.group(0)
            comp_name = entry["component"]
            if comp_name in seen_components:
                continue
            seen_components.add(comp_name)

            age = CURRENT_YEAR - entry["release_year"]
            findings.append({
                "component": comp_name,
                "detected_string": matched_str,
                "release_year": entry["release_year"],
                "age_years": age,
                "eol_status": entry["eol_status"],
                "cve_count": entry["cve_count"],
                "sample_cves": entry["sample_cves"],
                "recommendation": entry["recommendation"]
            })
            logger.warning(f"Obsolescence detected: {comp_name} ({matched_str}) -> {age} years old ({entry['eol_status']})")

    return findings
