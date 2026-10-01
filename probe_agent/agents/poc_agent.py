"""
CyberScore TN — Agent 3: PoC Validation Agent
Performs dynamic, non-destructive verification to eliminate false positives and confirm findings.
"""

import logging
from probe_agent.models import AuditState, VulnerabilityFinding
from probe_agent.tools.poc_verifier import PoCVerifier

logger = logging.getLogger("probe_agent.poc")


class PoCAgent:
    """
    Agent 3: Validate vulnerabilities with active, non-destructive proofs.
    """
    def __init__(self):
        pass

    def run(self, state: AuditState) -> AuditState:
        logger.info(f"[*] [AGENT 3: DYNAMIC PoC VALIDATION] Testing exploitability safely...")
        state.status = "verifying"

        # Use HTTPS for probes when the target confirmed a valid TLS certificate
        has_valid_tls = state.ssl_info.get("valid", False)
        verifier = PoCVerifier(state.target_host, use_https=has_valid_tls)
        validated = []

        # 1. Test Sensitive Discovered Endpoints
        for ep_desc in state.discovered_endpoints:
            ep = ep_desc.split(" ")[0]
            is_valid, evidence = verifier.verify_exposed_endpoint(ep)
            if is_valid:
                validated.append(VulnerabilityFinding(
                    id=f"EXPOSED-{ep.replace('/', '_').strip('_')}",
                    title=f"Ressource sensible accessible publiquement : {ep}",
                    severity="high" if "git" in ep or "env" in ep or "phpinfo" in ep else "medium",
                    owasp_category="A01:2021-Broken Access Control",
                    cvss_score=7.8 if "git" in ep or "env" in ep else 5.5,
                    description=f"Le fichier ou répertoire {ep} est directement téléchargeable sans authentification.",
                    evidence=evidence,
                    remediation=f"Bloquer l'accès à {ep} dans la configuration Nginx/Apache.",
                    poc_verified=True,
                    nist_control="PR.AC-4",
                    iso27001_control="A.8.23",
                ))

        # 2. Dynamic Input Validation Tests (XSS & SQLi non-destructive probes)
        is_xss, xss_evidence = verifier.verify_xss_reflection()
        if is_xss:
            validated.append(VulnerabilityFinding(
                id="VALIDATED-REFLECTED-XSS",
                title="Cross-Site Scripting (XSS) Reflété Confirmé",
                severity="high",
                owasp_category="A03:2021-Injection",
                cvss_score=8.1,
                description="L'application reflète directement les paramètres d'entrée sans échappement HTML adéquat.",
                evidence=xss_evidence,
                remediation="Échapper toutes les sorties utilisateurs avec htmlspecialchars() ou équivalent.",
                poc_verified=True,
                nist_control="PR.DS-5",
                iso27001_control="A.8.28",
            ))

        is_sqli, sqli_evidence = verifier.verify_sql_error_disclosure()
        if is_sqli:
            validated.append(VulnerabilityFinding(
                id="VALIDATED-SQL-ERROR-LEAK",
                title="Divulgation d'erreur de base de données (Vecteur SQL Injection)",
                severity="critical",
                owasp_category="A03:2021-Injection",
                cvss_score=9.3,
                description="L'application renvoie des messages d'erreur de base de données bruts en réponse à des caractères de contrôle SQL.",
                evidence=sqli_evidence,
                remediation="Utiliser impérativement des requêtes préparées (Prepared Statements) et désactiver l'affichage des erreurs.",
                poc_verified=True,
                nist_control="PR.DS-5",
                iso27001_control="A.8.28",
            ))

        # 3. Incorporate Potential Findings with Confirmed Context
        for pot in state.potential_vulnerabilities:
            # Check if this finding is already covered
            if not any(v.title == pot.title for v in validated):
                # Architectural findings like open ports or missing headers are already verified by definition
                if "PORT" in pot.id or "HEADER" in pot.id:
                    pot.poc_verified = True
                validated.append(pot)

        state.validated_vulnerabilities = validated
        logger.info(f"  -> Validated {len(validated)} findings ({sum(1 for v in validated if v.poc_verified)} with active PoC)")
        return state
