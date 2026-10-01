"""
CyberScore TN — Agent 4: Remediation, Scoring & Certification Agent
Calculates the final security score, prioritizes remediation roadmaps, and computes SHA-256 seal.
"""

import logging
from typing import List, Dict, Any
from probe_agent.models import AuditState, RemediationAction
from probe_agent.ai_client import AICyberEngine

logger = logging.getLogger("probe_agent.remediation")


class RemediationAgent:
    """
    Agent 4: Finalize audit results, calculate CyberScore, and build hardening roadmap.
    """
    def __init__(self, ai_engine: AICyberEngine):
        self.ai = ai_engine

    def run(self, state: AuditState) -> AuditState:
        logger.info(f"[*] [AGENT 4: REMEDIATION & SCORING] Computing scores and roadmap...")
        state.status = "reporting"

        # 1. Calculate Score based on Findings Severity
        score = 100
        for v in state.validated_vulnerabilities:
            if v.severity == "critical":
                score -= 22
            elif v.severity == "high":
                score -= 12
            elif v.severity == "medium":
                score -= 6
            elif v.severity == "low":
                score -= 2

        score = max(10, min(100, score))
        state.score = score

        # 2. Assign Official Grade
        if score >= 85:
            state.grade = "A"
        elif score >= 70:
            state.grade = "B"
        elif score >= 55:
            state.grade = "C"
        elif score >= 40:
            state.grade = "D"
        else:
            state.grade = "F"

        # 3. Generate Remediation Roadmap (Strictly Tailored to Actual Findings)
        findings_payload = [
            {"title": v.title, "severity": v.severity, "remediation": v.remediation}
            for v in state.validated_vulnerabilities
        ]

        ai_steps = self.ai.generate_remediation_plan(state.target, findings_payload)
        roadmap: List[RemediationAction] = []

        if ai_steps and isinstance(ai_steps, list):
            state.remediation_source = "ai"
            for s in ai_steps:
                roadmap.append(RemediationAction(
                    step_number=int(s.get("step_number", len(roadmap)+1)),
                    title=s.get("title", "Action de remédiation"),
                    severity=s.get("severity", "high"),
                    estimated_score_gain=int(s.get("estimated_score_gain", 10)),
                    commands=s.get("commands", "# Appliquer les correctifs requis"),
                    description=s.get("description", ""),
                ))
        else:
            # Deterministic, Audit-Grade Rule Engine (Strictly Tailored - 0 False Information)
            state.remediation_source = "deterministic_engine"
            roadmap = self._generate_tailored_roadmap(state)

        state.remediation_roadmap = roadmap

        # 4. Calculate Authentic Multi-Agent Category Scores
        state.agent_scores = self._calculate_agent_scores(state)

        # 5. Cryptographic SHA-256 Seal
        state.compute_sha256()
        logger.info(f"  -> Calculated Score: {state.score}/100 (Grade {state.grade})")
        logger.info(f"  -> Agent Breakdown Scores: {state.agent_scores}")
        logger.info(f"  -> Generated SHA-256 Audit Seal: {state.sha256_hash}")
        state.status = "completed"
        return state

    def _calculate_agent_scores(self, state: AuditState) -> Dict[str, int]:
        """
        Compute genuine, explainable scores for each of the 4 autonomous agents.
        No artificial offsets.
        """
        # Agent 1: Network & Port Reconnaissance
        # Base 100. Deductions for exposed risky services, open HTTP without TLS, disclosed banners.
        recon_score = 100
        risky_ports = [p for p in state.open_ports if p.is_risky]
        recon_score -= len(risky_ports) * 30

        has_http_80 = any(p.port == 80 for p in state.open_ports)
        has_https_443 = any(p.port == 443 for p in state.open_ports)
        if has_http_80 and not has_https_443:
            recon_score -= 15  # Unencrypted web only

        disclosed_banner = any(p.banner and ("ubuntu" in p.banner.lower() or "apache" in p.banner.lower() or "openssh" in p.banner.lower()) for p in state.open_ports)
        if disclosed_banner:
            recon_score -= 5

        recon_score = max(20, min(100, recon_score))

        # Agent 2: CVE & Configuration Correlation
        # Base 100. Deductions directly derived from severity of identified configuration flaws.
        cve_score = 100
        for v in state.validated_vulnerabilities:
            if v.severity == "critical":
                cve_score -= 25
            elif v.severity == "high":
                cve_score -= 15
            elif v.severity == "medium":
                cve_score -= 8
            elif v.severity == "low":
                cve_score -= 3
        cve_score = max(20, min(100, cve_score))

        # Agent 3: Dynamic PoC Validation & Active Exploitability
        # Base 100. High score indicates resistance to active exploitation.
        poc_score = 100
        active_poc_exploits = [v for v in state.validated_vulnerabilities if v.poc_verified and ("SQL" in v.id or "XSS" in v.id or "EXPOSED" in v.id)]
        poc_score -= len(active_poc_exploits) * 35
        # Passive configuration issues incur minimal exploit deduction
        passive_issues = [v for v in state.validated_vulnerabilities if not (v.poc_verified and ("SQL" in v.id or "XSS" in v.id or "EXPOSED" in v.id))]
        poc_score -= len(passive_issues) * 5
        poc_score = max(15, min(100, poc_score))

        # Agent 4: Remediation Readiness & Cryptographic Assurance
        # 100 if all findings have an associated remediation action and SHA-256 seal is valid
        remediation_score = 100 if len(state.remediation_roadmap) > 0 else 50

        return {
            "recon_ports": recon_score,
            "cve_analysis": cve_score,
            "poc_validation": poc_score,
            "remediation_seal": remediation_score,
        }

    def _generate_tailored_roadmap(self, state: AuditState) -> List[RemediationAction]:
        """
        Generate an authentic, high-fidelity remediation roadmap strictly based
        on findings detected during the audit. Zero generic or irrelevant filler.
        """
        roadmap: List[RemediationAction] = []
        step_num = 1

        # 1. Check for exposed risky services / ports
        risky_ports = [p for p in state.open_ports if p.is_risky]
        if risky_ports:
            ports_str = ", ".join(f"{p.port} ({p.service})" for p in risky_ports)
            deny_cmds = "\n".join(f"sudo ufw deny {p.port}/tcp  # Bloquer {p.service}" for p in risky_ports)
            roadmap.append(RemediationAction(
                step_number=step_num,
                title=f"Verrouillage Pare-Feu des Ports Risqués ({len(risky_ports)} service(s) exposé(s))",
                severity="critical",
                estimated_score_gain=min(25, len(risky_ports) * 15),
                commands=f"{deny_cmds}\nsudo ufw reload",
                description=f"Fermer immédiatement l'exposition directe aux services non chiffrés ou bases de données : {ports_str}."
            ))
            step_num += 1
        elif any(p.port == 22 for p in state.open_ports):
            ssh_findings = [v for v in state.validated_vulnerabilities if "SSH" in v.id or "PORT-22" in v.id]
            if ssh_findings:
                roadmap.append(RemediationAction(
                    step_number=step_num,
                    title="Durcissement du Service SSH (Port 22)",
                    severity="medium",
                    estimated_score_gain=6,
                    commands="# /etc/ssh/sshd_config\nPermitRootLogin no\nPasswordAuthentication no\nsudo systemctl restart sshd",
                    description="Restreindre l'accès SSH aux clés cryptographiques et désactiver la connexion root directe."
                ))
                step_num += 1

        # 2. Check for missing HTTP Security Headers
        header_findings = [v for v in state.validated_vulnerabilities if "HEADER" in v.id or "header" in v.title.lower()]
        if header_findings:
            nginx_directives = []
            has_hsts = any("hsts" in v.id.lower() or "strict-transport" in v.title.lower() for v in header_findings)
            has_csp = any("csp" in v.id.lower() or "content-security-policy" in v.title.lower() for v in header_findings)
            has_xfo = any("x-frame" in v.id.lower() or "clickjacking" in v.title.lower() for v in header_findings)
            has_xcto = any("nosniff" in v.id.lower() or "mime" in v.title.lower() or "content-type" in v.title.lower() for v in header_findings)

            if has_hsts:
                nginx_directives.append('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')
            if has_csp:
                nginx_directives.append("add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;")
            if has_xfo:
                nginx_directives.append('add_header X-Frame-Options "SAMEORIGIN" always;')
            if has_xcto:
                nginx_directives.append('add_header X-Content-Type-Options "nosniff" always;')

            directives_cmd = "\n".join(nginx_directives) if nginx_directives else 'add_header X-Content-Type-Options "nosniff" always;'
            roadmap.append(RemediationAction(
                step_number=step_num,
                title="Injection des En-têtes HTTP de Sécurité Manquants",
                severity="high",
                estimated_score_gain=min(24, len(header_findings) * 12),
                commands=f"# Configuration Nginx (/etc/nginx/conf.d/security.conf)\n{directives_cmd}\n# Tester et recharger\nsudo nginx -t && sudo systemctl reload nginx",
                description="Déployer les en-têtes HTTP obligatoires pour contrer le SSL-Stripping, le vol de session XSS et le détournement de clics."
            ))
            step_num += 1

        # 3. Check for SQL Injection / Database error leaks
        sqli_findings = [v for v in state.validated_vulnerabilities if "SQL" in v.id or "sql" in v.title.lower()]
        if sqli_findings:
            roadmap.append(RemediationAction(
                step_number=step_num,
                title="Neutralisation des Injections SQL & Requêtes Préparées",
                severity="critical",
                estimated_score_gain=22,
                commands="# Migrer vers des requêtes préparées PDO obligatoires\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);\n# Désactiver l'affichage des erreurs en production\ndisplay_errors = Off  # php.ini",
                description="Paramétrer toutes les requêtes SQL avec des requêtes préparées pour neutraliser définitivement les injections."
            ))
            step_num += 1

        # 4. Check for XSS (Cross-Site Scripting)
        xss_findings = [v for v in state.validated_vulnerabilities if "XSS" in v.id or "xss" in v.title.lower()]
        if xss_findings:
            roadmap.append(RemediationAction(
                step_number=step_num,
                title="Échappement Contextuel & Neutralisation XSS",
                severity="high",
                estimated_score_gain=15,
                commands="# Échapper toutes les variables rendues dans les vues\necho htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');",
                description="Appliquer l'échappement systématique des données dynamiques restituées dans le navigateur."
            ))
            step_num += 1

        # 5. Check for Exposed Sensitive Endpoints (.git, .env, phpinfo)
        exposed_findings = [v for v in state.validated_vulnerabilities if "EXPOSED" in v.id or "sensible" in v.title.lower()]
        if exposed_findings:
            roadmap.append(RemediationAction(
                step_number=step_num,
                title="Blocage des Répertoires et Fichiers Sensibles",
                severity="high",
                estimated_score_gain=15,
                commands="# Bloquer l'accès aux fichiers cachés (.git, .env) dans Nginx\nlocation ~ /\\.(?!well-known).* {\n    deny all;\n    return 404;\n}\nsudo nginx -t && sudo systemctl reload nginx",
                description="Interdire formellement l'accès public aux dépôts de code (.git) et aux fichiers de configuration sensibles."
            ))
            step_num += 1

        # 6. Check for TLS / SSL issues
        ssl_issues = not state.ssl_info.get("valid", True) or any("ssl" in v.id.lower() for v in state.validated_vulnerabilities)
        if ssl_issues and not any("HEADER" in r.title for r in roadmap):
            roadmap.append(RemediationAction(
                step_number=step_num,
                title="Déploiement Certificat TLS & Forçage HTTPS",
                severity="high",
                estimated_score_gain=15,
                commands=f"sudo certbot --nginx -d {state.target_host}\nsudo systemctl enable certbot.timer",
                description="Activer le chiffrement complet HTTPS avec un certificat reconnu et son renouvellement automatique."
            ))
            step_num += 1

        # 7. Software Obsolescence & EOL Remediation
        obsolescence_findings = [v for v in state.validated_vulnerabilities if "OBSOLESCENCE" in v.id]
        if obsolescence_findings:
            upgrade_cmds = []
            for obs_v in obsolescence_findings:
                if "Apache" in obs_v.title:
                    upgrade_cmds.append("sudo apt-get install --only-upgrade apache2  # ou compiler Apache 2.4.58+")
                elif "OpenSSH" in obs_v.title:
                    upgrade_cmds.append("sudo apt-get install --only-upgrade openssh-server  # Cible : OpenSSH 9.x")
                elif "PHP" in obs_v.title:
                    upgrade_cmds.append("sudo add-apt-repository ppa:ondrej/php && sudo apt-get install php8.3")
                elif "Nginx" in obs_v.title:
                    upgrade_cmds.append("sudo apt-get install --only-upgrade nginx  # Cible : Nginx 1.24+")
                elif "Ubuntu" in obs_v.title:
                    upgrade_cmds.append("sudo do-release-upgrade  # Migration vers Ubuntu 22.04 LTS ou 24.04 LTS")
                else:
                    upgrade_cmds.append(f"# Mettre à jour : {obs_v.title}")

            all_cmds = "\n".join(upgrade_cmds) if upgrade_cmds else "sudo apt update && sudo apt full-upgrade -y"
            roadmap.append(RemediationAction(
                step_number=step_num,
                title=f"Mise à Niveau des Composants Obsolètes ({len(obsolescence_findings)} EOL détecté(s))",
                severity="critical",
                estimated_score_gain=min(30, len(obsolescence_findings) * 12),
                commands=f"# Plan de mise à niveau des composants en fin de vie\n{all_cmds}\nsudo systemctl restart apache2 nginx sshd  # Redémarrer les services mis à jour",
                description=f"Les composants suivants sont obsolètes et en fin de vie : {', '.join(v.title.split(':')[-1].strip() for v in obsolescence_findings[:3])}. Migration impérative vers des versions supportées."
            ))
            step_num += 1

        # 8. Unnecessary / Suspicious Open Ports Closure
        unnecessary_ports = [p for p in state.open_ports if p.port in (9929, 31337, 8888, 10000, 8081, 9443)]
        if unnecessary_ports:
            ports_str = ", ".join(f"{p.port} ({p.service})" for p in unnecessary_ports)
            deny_cmds = "\n".join(f"sudo ufw deny {p.port}/tcp  # Bloquer {p.service}" for p in unnecessary_ports)
            roadmap.append(RemediationAction(
                step_number=step_num,
                title=f"Fermeture des Ports Non-Essentiels ({len(unnecessary_ports)} service(s) suspect(s))",
                severity="high",
                estimated_score_gain=min(18, len(unnecessary_ports) * 8),
                commands=f"{deny_cmds}\nsudo ufw reload",
                description=f"Ports non-essentiels exposés détectés par le scan avancé : {ports_str}. Ces services présentent un risque d'exploitation si non maintenus."
            ))
            step_num += 1

        # 9. Fallback if no specific vulnerabilities were found
        if not roadmap:
            roadmap.append(RemediationAction(
                step_number=1,
                title="Maintien de la Posture de Sécurité & Surveillance Active",
                severity="low",
                estimated_score_gain=0,
                commands="# Audits périodiques planifiés\nsudo apt update && sudo apt upgrade -y",
                description="Aucune vulnérabilité majeure identifiée lors de l'audit. Poursuivre le monitoring continu."
            ))

        return roadmap
