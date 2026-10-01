"""
CyberScore TN — Agent 2: CVE & Vulnerability Correlation Agent
Correlates discovered services and technologies with known vulnerabilities using Host AI.
"""

import logging
from typing import List, Dict, Any
from probe_agent.models import AuditState, VulnerabilityFinding
from probe_agent.ai_client import AICyberEngine

logger = logging.getLogger("probe_agent.cve")


class CVEAgent:
    """
    Agent 2: Reason over reconnaissance data using local Ollama model.
    """
    def __init__(self, ai_engine: AICyberEngine):
        self.ai = ai_engine

    def run(self, state: AuditState) -> AuditState:
        logger.info(f"[*] [AGENT 2: CVE & VULNERABILITY ANALYSIS] Correlating findings with AI...")
        state.status = "analyzing"

        findings: List[VulnerabilityFinding] = []

        # 1. Deterministic Security Rules for Exposed Ports
        for p in state.open_ports:
            if p.is_risky:
                findings.append(VulnerabilityFinding(
                    id=f"PORT-{p.port}-EXPOSED",
                    title=f"Service à haut risque exposé : Port {p.port} ({p.service})",
                    severity=p.severity,
                    owasp_category="A05:2021-Security Misconfiguration",
                    cvss_score=8.5 if p.severity == "critical" else 7.0,
                    description=f"Le port {p.port} ({p.service}) est exposé publiquement sur Internet sans tunnel sécurisé.",
                    evidence=f"Port: {p.port}/TCP, Bannière: '{p.banner}'",
                    remediation=f"Bloquer le port {p.port} via Firewalld/UFW ou restreindre l'accès par VPN.",
                    nist_control="PR.PT-3",
                    iso27001_control="A.8.20",
                ))

        # 2. Check for Missing HTTP Security Headers
        headers_lower = {k.lower(): v for k, v in state.headers.items()}
        if "strict-transport-security" not in headers_lower:
            findings.append(VulnerabilityFinding(
                id="HEADER-HSTS-MISSING",
                title="Absence du header HTTP Strict-Transport-Security (HSTS)",
                severity="high",
                owasp_category="A05:2021-Security Misconfiguration",
                cvss_score=7.4,
                description="Le site ne force pas l'usage exclusif du protocole HTTPS, permettant les attaques de type SSL-Stripping.",
                evidence="Header 'Strict-Transport-Security' absent de la réponse HTTP",
                remediation="Ajouter 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' dans Nginx.",
                nist_control="PR.DS-2",
                iso27001_control="A.8.24",
            ))

        if "content-security-policy" not in headers_lower:
            findings.append(VulnerabilityFinding(
                id="HEADER-CSP-MISSING",
                title="Absence de politique Content-Security-Policy (CSP)",
                severity="high",
                owasp_category="A03:2021-Injection",
                cvss_score=7.1,
                description="Aucune politique CSP n'est définie pour restreindre l'exécution de scripts non autorisés (vecteur XSS).",
                evidence="Header 'Content-Security-Policy' absent",
                remediation="Définir une politique CSP restrictive avec 'default-src \'self\'' dans la configuration web.",
                nist_control="PR.IP-1",
                iso27001_control="A.8.20",
            ))

        # 3. Software Obsolescence → Vulnerability Injection
        for obs in getattr(state, 'software_obsolescence', []):
            eol_status = obs.get("eol_status", "UNKNOWN")
            age = obs.get("age_years", 0)
            component = obs.get("component", "Unknown Component")
            cves = obs.get("sample_cves", [])

            # Assign severity based on age and EOL status
            if eol_status == "CRITICAL_OBSOLETE" or age >= 12:
                sev = "critical"
                cvss = 9.1
            elif eol_status == "END_OF_LIFE_OBSOLETE" or age >= 8:
                sev = "high"
                cvss = 8.0
            elif eol_status == "END_OF_LIFE" or age >= 5:
                sev = "high"
                cvss = 7.5
            else:
                sev = "medium"
                cvss = 6.0

            cve_str = ", ".join(cves[:3]) if cves else "N/A"
            findings.append(VulnerabilityFinding(
                id=f"OBSOLESCENCE-{component.replace(' ', '-').upper()[:30]}",
                title=f"Composant obsolète détecté : {component} ({obs.get('detected_string', '')})",
                severity=sev,
                owasp_category="A06:2021-Vulnerable and Outdated Components",
                cvss_score=cvss,
                description=f"Le composant {component} (version détectée : '{obs.get('detected_string', '')}', sortie en {obs.get('release_year', '?')}) est obsolète depuis {age} ans. Statut : {eol_status}. {obs.get('cve_count', 0)} CVE historiques connues.",
                evidence=f"Bannière/Version : '{obs.get('detected_string', '')}', Ancienneté : {age} ans, CVE exemples : {cve_str}",
                remediation=obs.get("recommendation", f"Mettre à jour {component} vers la dernière version supportée."),
                nist_control="ID.RA-1",
                iso27001_control="A.8.8",
            ))
            logger.warning(f"  -> Obsolescence finding: {component} ({age}y, {eol_status}) → {sev}")

        # 4. Contextual AI Reasoning with Host Ollama LLM
        ports_summary = [{"port": p.port, "service": p.service, "banner": p.banner} for p in state.open_ports]
        ai_vulns = self.ai.analyze_vulnerabilities(
            target_host=state.target_host,
            open_ports=ports_summary,
            technologies=state.technologies,
            headers=state.headers
        )

        for v in ai_vulns:
            v_id = v.get("id") or f"AI-VULN-{len(findings)+1}"
            # Avoid duplicate titles
            if not any(f.title.lower() == v.get("title", "").lower() for f in findings):
                findings.append(VulnerabilityFinding(
                    id=v_id,
                    title=v.get("title", "Vulnérabilité détectée"),
                    severity=v.get("severity", "medium").lower(),
                    owasp_category=v.get("owasp_category", "A05:2021"),
                    cvss_score=float(v.get("cvss_score", 6.5)),
                    description=v.get("description", ""),
                    evidence=v.get("evidence", "Détecté par inférence IA"),
                    remediation=v.get("remediation", "Mettre à jour les composants applicatifs."),
                    poc_verified=False,
                ))

        state.potential_vulnerabilities = findings
        logger.info(f"  -> Identified {len(findings)} potential vulnerabilities")
        return state
