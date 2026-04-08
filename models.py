"""Data models for the IAM Security Tester."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
import uuid


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    def __lt__(self, other):
        return self.rank < other.rank


SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff4444",
    Severity.HIGH: "#ff8c00",
    Severity.MEDIUM: "#ffd700",
    Severity.LOW: "#4dabf7",
    Severity.INFO: "#868e96",
}


@dataclass
class Finding:
    category: str
    name: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    endpoint: Optional[str] = None
    request_method: Optional[str] = None
    response_code: Optional[int] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class TestResult:
    module_name: str
    category: str
    findings: List[Finding] = field(default_factory=list)
    tests_run: int = 0
    tests_passed: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class ScanResult:
    target_url: str
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: Optional[datetime] = None
    module_results: List[TestResult] = field(default_factory=list)

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for r in self.module_results:
            findings.extend(r.findings)
        return sorted(findings, key=lambda f: f.severity)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def findings_by_severity(self) -> Dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity] += 1
        return counts

    @property
    def total_tests(self) -> int:
        return sum(r.tests_run for r in self.module_results)

    @property
    def duration(self) -> float:
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0.0


# ── Breach Simulation Models ──

class KillChainPhase(Enum):
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    EXFILTRATION = "Exfiltration"


@dataclass
class AttackStep:
    phase: KillChainPhase
    name: str
    module_key: str
    method_name: str
    description: str
    depends_on_success: bool = False
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    status: str = "pending"  # pending | running | success | failed | skipped
    finding: Optional[Finding] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


@dataclass
class BreachScenario:
    id: str
    name: str
    description: str
    icon: str
    steps: List[AttackStep] = field(default_factory=list)

    @property
    def kill_chain_phases(self) -> List[KillChainPhase]:
        seen = []
        for s in self.steps:
            if s.phase not in seen:
                seen.append(s.phase)
        return seen


@dataclass
class BreachSimulationResult:
    scenario: BreachScenario
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    steps_completed: int = 0
    breach_successful: bool = False

    @property
    def duration(self) -> float:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0

    @property
    def findings(self) -> List[Finding]:
        return [s.finding for s in self.scenario.steps if s.finding]


# ── Self-Healing Models ──

class HealingStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    VERIFIED = "verified"


HEALING_STATUS_COLORS = {
    HealingStatus.PENDING: "#7a8599",
    HealingStatus.IN_PROGRESS: "#3b82f6",
    HealingStatus.SUCCESS: "#22c55e",
    HealingStatus.FAILED: "#ff4444",
    HealingStatus.VERIFIED: "#a855f7",
}


@dataclass
class HealingAction:
    id: str
    finding_id: str
    finding_name: str
    finding_category: str
    finding_severity: Severity
    action_type: str  # isolate_agent, rotate_tokens, restore_config, etc.
    description: str
    api_endpoint: str
    api_method: str  # POST, PUT, DELETE
    api_payload: Dict[str, Any] = field(default_factory=dict)
    status: HealingStatus = HealingStatus.PENDING
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    verification_result: Optional[str] = None
