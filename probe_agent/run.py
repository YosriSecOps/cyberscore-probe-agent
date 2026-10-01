"""
CyberScore TN — Standalone Probe CLI Runner
Can be executed directly on the Host (Windows) or inside the RHEL 9.5 VM probe.
"""

import os
import sys
import json
import asyncio
import argparse
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from probe_agent.orchestrator import PentestOrchestrator


def print_banner():
    print("""
======================================================================
     CYBERSCORE TN -- AUTONOMOUS SECURITY PENTEST PROBE
   Multi-Agent Architecture & Local Sovereign AI Orchestration
        Reference : TEK-UP SSIRF & ANCS National Framework
=====================================================================""")


def print_summary_card(state):
    def color_sev(sev):
        s = sev.lower()
        if s == "critical": return "\033[1;31m[CRITICAL]\033[0m"
        if s == "high": return "\033[1;33m[HIGH]    \033[0m"
        if s == "medium": return "\033[1;34m[MEDIUM]  \033[0m"
        return "\033[1;32m[LOW]     \033[0m"

    grade_color = "\033[1;32m" if state.grade in ("A", "B") else "\033[1;33m" if state.grade == "C" else "\033[1;31m"

    print("\n" + "="*70)
    print(f"\033[1mRÉSULTATS DE L'AUDIT DE SÉCURITÉ — {state.target_host}\033[0m")
    print(f"ID d'Audit       : {state.scan_id}")
    print(f"Adresse IP       : {state.ip_address}")
    print(f"Durée d'Analyse  : {state.duration_seconds} secondes")
    print(f"Score National   : {grade_color}{state.score}/100 (Grade {state.grade})\033[0m")
    print(f"Empreinte SHA256 : \033[36m{state.sha256_hash}\033[0m")
    print("="*70)

    print("\n\033[1m1. CARTOGRAPHIE DES PORTS & SERVICES RÉSEAU :\033[0m")
    if state.open_ports:
        for p in state.open_ports:
            risk = "\033[31m[RISQUE ÉLEVÉ]\033[0m" if p.is_risky else "\033[32m[NORMAL]\033[0m"
            print(f"  • Port {p.port:5d}/TCP : {p.service:<15} {risk} {p.banner[:50]}")
    else:
        print("  • Aucun port public ouvert détecté sur la plage testée.")

    print("\n\033[1m2. VULNÉRABILITÉS VALIDÉES (TRIÉES PAR GRAVITÉ) :\033[0m")
    if state.validated_vulnerabilities:
        for v in state.validated_vulnerabilities:
            poc_tag = "\033[1;32m[PoC CONFIRMÉ]\033[0m" if v.poc_verified else "[THÉORIQUE]"
            print(f"  {color_sev(v.severity)} {v.title} (CVSS {v.cvss_score}) {poc_tag}")
            print(f"       OWASP: {v.owasp_category} | NIST: {v.nist_control}")
            if v.evidence:
                print(f"       \033[90mPreuve: {v.evidence[:90]}\033[0m")
    else:
        print("  • Aucune vulnérabilité critique détectée sur cette cible.")

    print("\n\033[1m3. FEUILLE DE ROUTE DE REMÉDIATION TECHNIQUE (ACTION PLAN) :\033[0m")
    for step in state.remediation_roadmap:
        print(f"\n  [\033[1;36mÉTAPE {step.step_number}\033[0m] {step.title} (\033[32m+{step.estimated_score_gain} pts\033[0m)")
        print(f"  Description: {step.description}")
        print("  \033[1mCommandes d'exécution immédiate :\033[0m")
        for line in step.commands.strip().split("\n"):
            print(f"    \033[33m$ {line}\033[0m")

    print("\n" + "="*70 + "\n")


async def main():
    parser = argparse.ArgumentParser(description="CyberScore TN Autonomous Pentest Probe")
    parser.add_argument("--target", "-t", default="testphp.vulnweb.com", help="Target URL or Hostname to audit")
    parser.add_argument("--model", "-m", default=None, help="Ollama model name (default: qwen2.5-coder:7b)")
    parser.add_argument("--out", "-o", default="reports", help="Directory to save audit reports")

    args = parser.parse_args()
    print_banner()

    orchestrator = PentestOrchestrator(ai_model=args.model)
    state = await orchestrator.execute_audit(args.target)

    if state.status == "failed":
        print(f"\n\033[1;31m[!] ÉCHEC DE L'AUDIT : Impossible d'auditer '{args.target}'. Vérifiez que l'hôte existe et est joignable sur Internet.\033[0m\n")
        sys.exit(1)

    print_summary_card(state)

    # Save report to JSON file
    os.makedirs(args.out, exist_ok=True)
    report_file = os.path.join(args.out, f"audit_{state.scan_id}.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)

    print(f"\033[32m[✓] Rapport complet enregistré avec succès dans : {report_file}\033[0m\n")


if __name__ == "__main__":
    asyncio.run(main())
