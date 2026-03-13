"""Data models for the IAM Security Tester."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional
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
