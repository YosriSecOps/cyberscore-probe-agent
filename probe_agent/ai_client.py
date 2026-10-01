"""
CyberScore TN — Decoupled AI Client (AIaaS)
Interfaces with the Host's Ollama instance (qwen2.5-coder:7b) via REST API.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from probe_agent.config import CANDIDATE_AI_URLS, OLLAMA_MODEL

logger = logging.getLogger("probe_agent.ai")


class AICyberEngine:
    """
    Decoupled AI reasoning engine running against Host LLM.
    """
    def __init__(self, model: str = OLLAMA_MODEL):
        self.model = model
        self.active_url: Optional[str] = None
        self._detect_active_endpoint()

    def _detect_active_endpoint(self) -> Optional[str]:
        """Auto-probe candidate endpoints to find the active Ollama host."""
        for url in CANDIDATE_AI_URLS:
            try:
                req = urllib.request.Request(f"{url}/api/tags", headers={"User-Agent": "CyberScore-Probe/1.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        models = [m.get("name", "") for m in data.get("models", [])]
                        logger.info(f"Connected to Ollama at {url}. Available models: {models}")
                        self.active_url = url
                        # Pick best available model if requested is not present
                        if self.model not in models and models:
                            self.model = models[0]
                        return url
            except Exception:
                continue

        logger.warning("No active Ollama endpoint discovered. Using autonomous security fallback engine.")
        return None

    def query(self, prompt: str, system_prompt: Optional[str] = None, json_format: bool = True) -> Dict[str, Any]:
        """
        Send an inference request to Ollama.
        """
        if not self.active_url:
            self._detect_active_endpoint()

        if not self.active_url:
            return {"error": "AI_OFFLINE", "raw": "Ollama host unreachable"}

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Strictly deterministic
                "top_p": 0.9,
                "num_predict": 250,  # Ensure rapid, bounded completion
                "num_ctx": 2048,
            }
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_format:
            payload["format"] = "json"

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.active_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "CyberScore-Probe/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                result = json.loads(resp.read().decode())
                response_text = result.get("response", "{}")
                if json_format:
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError:
                        return {"raw": response_text}
                return {"raw": response_text}
        except Exception as e:
            logger.error(f"Error querying AI engine: {e}")
            return {"error": str(e)}

    def analyze_vulnerabilities(self, target_host: str, open_ports: List[Dict[str, Any]], technologies: List[str], headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Agent 2: Reason over reconnaissance data and identify CVEs.
        """
        system = """You are an elite national cyber defense penetration tester and vulnerability researcher.
Analyze the target's network reconnaissance data and return a strictly valid JSON list of vulnerabilities.
Format:
{
  "vulnerabilities": [
    {
      "id": "CVE-XXXX-XXXX or MISC-XXXX",
      "title": "Clear vulnerability title",
      "severity": "critical|high|medium|low",
      "owasp_category": "A01|A02|A03|A04|A05|A06|A07|A08|A09|A10",
      "cvss_score": 7.5,
      "description": "Technical analysis of the vulnerability based on exposed service or headers",
      "evidence": "Observed port or header triggering this finding",
      "remediation": "Exact configuration or patch steps required"
    }
  ]
}"""

        prompt = f"""Target Host: {target_host}
Open Ports: {json.dumps(open_ports)}
Detected Technologies: {json.dumps(technologies)}
HTTP Response Headers: {json.dumps(headers)}

Perform in-depth vulnerability correlation. Focus on:
1. Missing essential HTTP security headers (HSTS, CSP, X-Frame-Options).
2. Outdated software versions, unencrypted services (FTP, Telnet, HTTP cleartext).
3. Known vulnerabilities in detected stacks (e.g. PHP 5/7 CVEs, Apache path traversal, SQL injection attack surface).
Return JSON only."""

        res = self.query(prompt, system_prompt=system, json_format=True)
        if "vulnerabilities" in res and isinstance(res["vulnerabilities"], list):
            return res["vulnerabilities"]
        
        # Fallback if AI output lacked root key
        if isinstance(res, list):
            return res
        return []

    def generate_remediation_plan(self, target: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Agent 4: Generate concrete remediation commands and action steps.
        """
        system = """You are a senior Linux system administrator and DevSecOps engineer.
Given a list of confirmed security findings, provide a structured 4-step hardening roadmap.
For each step, include real, copy-pasteable Bash / Nginx / Apache / UFW configuration commands.
Format:
{
  "steps": [
    {
      "step_number": 1,
      "title": "Immediate Critical Patch / Port Lockdown",
      "severity": "critical",
      "estimated_score_gain": 15,
      "commands": "# exact bash or nginx commands",
      "description": "Why this is necessary and what it achieves"
    }
  ]
}"""

        prompt = f"""Target: {target}
Confirmed Findings: {json.dumps(findings[:8])}

Generate the prioritized remediation roadmap with exact configuration commands. Return JSON only."""

        res = self.query(prompt, system_prompt=system, json_format=True)
        if "steps" in res and isinstance(res["steps"], list):
            return res["steps"]
        return []
