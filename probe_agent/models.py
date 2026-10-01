"""
CyberScore TN — Autonomous Pentest Probe Models
Defines the shared AuditState object and structured security entities.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib
import json


@dataclass
class PortFinding:
    port: int
    service: str
    state: str = "open"
    banner: str = ""
    is_risky: bool = False
    severity: str = "low"  # info, low, medium, high, critical


@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    owasp_category: str
    cve_id: Optional[str] = None
    cvss_score: float = 0.0
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    poc_verified: bool = False
    nist_control: str = "PR.PT-3"
    iso27001_control: str = "A.8.20"


@dataclass
class RemediationAction:
    step_number: int
    title: str
    severity: str
    estimated_score_gain: int
    commands: str
    description: str


@dataclass
class AuditState:
    """
    Shared state object flowing across the 4 autonomous agents.
    """
    scan_id: str
    target: str
    target_host: str
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    status: str = "initialized"  # initialized, recon, analyzing, verifying, reporting, completed, failed
    
    # Agent 1 outputs (Reconnaissance)
    ip_address: str = ""
    ipv6_address: Optional[str] = None
    open_ports: List[PortFinding] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    discovered_endpoints: List[str] = field(default_factory=list)
    os_detection: Dict[str, Any] = field(default_factory=dict)
    software_obsolescence: List[Dict[str, Any]] = field(default_factory=list)
    web_surface: Dict[str, Any] = field(default_factory=dict)

    # Agent 2 outputs (CVE & Vulnerability Analysis)
    potential_vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    ai_raw_analysis: str = ""

    # Agent 3 outputs (PoC Validation)
    validated_vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    poc_logs: List[str] = field(default_factory=list)

    # Agent 4 outputs (Remediation, Scoring & Certification)
    score: int = 100
    grade: str = "A"
    remediation_roadmap: List[RemediationAction] = field(default_factory=list)
    remediation_source: str = "deterministic_engine"
    agent_scores: Dict[str, int] = field(default_factory=dict)
    sha256_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to serializable dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_host": self.target_host,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "network": {
                "ip_address": self.ip_address,
                "ipv6_address": self.ipv6_address,
                "open_ports": [p.__dict__ for p in self.open_ports],
                "technologies": self.technologies,
                "discovered_endpoints": self.discovered_endpoints,
                "ssl_info": self.ssl_info,
                "os_detection": self.os_detection,
                "software_obsolescence": self.software_obsolescence,
                "web_surface": self.web_surface,
            },
            "findings": [v.__dict__ for v in self.validated_vulnerabilities],
            "scoring": {
                "score": self.score,
                "grade": self.grade,
                "critical_count": sum(1 for v in self.validated_vulnerabilities if v.severity == "critical"),
                "high_count": sum(1 for v in self.validated_vulnerabilities if v.severity == "high"),
                "medium_count": sum(1 for v in self.validated_vulnerabilities if v.severity == "medium"),
                "low_count": sum(1 for v in self.validated_vulnerabilities if v.severity == "low"),
            },
            "agent_scores": self.agent_scores,
            "remediation_source": self.remediation_source,
            "remediation_roadmap": [r.__dict__ for r in self.remediation_roadmap],
            "sha256_hash": self.sha256_hash,
        }

    def compute_sha256(self) -> str:
        """Compute cryptographic hash of the audit findings."""
        content = json.dumps({
            "target": self.target,
            "findings": [v.__dict__ for v in self.validated_vulnerabilities],
            "score": self.score,
            "grade": self.grade,
        }, sort_keys=True)
        self.sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return self.sha256_hash
