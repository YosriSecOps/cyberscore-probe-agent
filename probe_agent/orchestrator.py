"""
CyberScore TN — Multi-Agent Pentest Orchestrator
Coordinates the 4-agent state graph pipeline and handles audit lifecycle.
"""

import time
import uuid
import logging
from datetime import datetime
from typing import Optional, Callable, Dict, Any

from probe_agent.models import AuditState
from probe_agent.ai_client import AICyberEngine
from probe_agent.agents.recon_agent import ReconAgent
from probe_agent.agents.cve_agent import CVEAgent
from probe_agent.agents.poc_agent import PoCAgent
from probe_agent.agents.remediation_agent import RemediationAgent

logger = logging.getLogger("probe_agent.orchestrator")


class PentestOrchestrator:
    """
    Coordinates the 4-tier autonomous security audit graph.
    """
    def __init__(self, ai_model: Optional[str] = None):
        self.ai = AICyberEngine(model=ai_model) if ai_model else AICyberEngine()
        self.recon_agent = ReconAgent()
        self.cve_agent = CVEAgent(self.ai)
        self.poc_agent = PoCAgent()
        self.remediation_agent = RemediationAgent(self.ai)

    async def execute_audit(
        self,
        target_url_or_host: str,
        progress_callback: Optional[Callable[[str, str, int], None]] = None
    ) -> AuditState:
        """
        Execute full multi-agent pentest lifecycle on target.
        """
        start_time = time.time()

        # Sanitize target into host
        clean_host = (
            target_url_or_host.strip()
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
        )

        scan_id = f"CYBER-{uuid.uuid4().hex[:8].upper()}"
        state = AuditState(
            scan_id=scan_id,
            target=target_url_or_host,
            target_host=clean_host,
            start_time=datetime.utcnow().isoformat(),
        )

        def report_step(step_name: str, message: str, pct: int):
            logger.info(f"[{pct}%] {step_name}: {message}")
            if progress_callback:
                try:
                    progress_callback(step_name, message, pct)
                except Exception:
                    pass

        try:
            # ── AGENT 1: RECONNAISSANCE ─────────────────────────────
            report_step("RECON", f"Cartographie réseau et bannières sur {clean_host}...", 15)
            state = await self.recon_agent.run(state)

            # ── AGENT 2: CVE & VULNERABILITY CORRELATION ─────────────
            report_step("ANALYSIS", f"Analyse contextuelle des vulnérabilités avec l'IA...", 45)
            state = self.cve_agent.run(state)

            # ── AGENT 3: DYNAMIC PoC VALIDATION ─────────────────────
            report_step("VERIFICATION", "Validation dynamique non-destructive des failles...", 75)
            state = self.poc_agent.run(state)

            # ── AGENT 4: REMEDIATION & SCORING ──────────────────────
            report_step("REPORTING", "Calcul du score de risque, feuille de route et scellement SHA-256...", 90)
            state = self.remediation_agent.run(state)

            report_step("COMPLETED", f"Audit terminé avec succès. Score: {state.score}/100", 100)

        except Exception as e:
            logger.error(f"Audit failed with exception: {e}", exc_info=True)
            state.status = "failed"
            report_step("FAILED", f"Erreur critique lors de l'audit: {str(e)[:100]}", 0)

        finally:
            state.end_time = datetime.utcnow().isoformat()
            state.duration_seconds = round(time.time() - start_time, 2)

        return state
