"""Test runner orchestrator."""

import time
import uuid
import requests
from datetime import datetime
from typing import List, Optional, Tuple
from models import ScanResult, TestResult, Finding, Severity
from config import ScanConfig
from http_client import SecurityTestClient

from attacks.authentication import AuthenticationAttacks
from attacks.authorization import AuthorizationAttacks
from attacks.api_security import APISecurityAttacks
from attacks.cryptographic import CryptographicAttacks
from attacks.injection import InjectionAttacks
from attacks.xss import XSSAttacks
from attacks.session import SessionAttacks
from attacks.information_disclosure import InformationDisclosureAttacks
from attacks.input_validation import InputValidationAttacks
from attacks.business_logic import BusinessLogicAttacks
from attacks.dos_ratelimit import DoSRateLimitAttacks
from attacks.compliance import ComplianceAttacks

# Ordered by priority (most critical first)
ATTACK_MODULES = [
    ("authentication", AuthenticationAttacks),
    ("authorization", AuthorizationAttacks),
    ("api_security", APISecurityAttacks),
    ("cryptographic", CryptographicAttacks),
    ("injection", InjectionAttacks),
    ("session", SessionAttacks),
    ("information_disclosure", InformationDisclosureAttacks),
    ("xss", XSSAttacks),
    ("input_validation", InputValidationAttacks),
    ("business_logic", BusinessLogicAttacks),
    ("dos_ratelimit", DoSRateLimitAttacks),
    ("compliance", ComplianceAttacks),
]

ALL_CATEGORIES = [name for name, _ in ATTACK_MODULES]


class TestRunner:
    """Orchestrates security test execution."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = SecurityTestClient(
            base_url=config.target_url,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
        )

    def check_connectivity(self) -> Tuple[bool, str]:
        return self.client.check_connectivity()

    def get_modules(self):
        """Get filtered list of modules to run."""
        modules = ATTACK_MODULES
        if self.config.categories:
            modules = [(n, c) for n, c in modules if n in self.config.categories]
        if self.config.skip_dos:
            modules = [(n, c) for n, c in modules if n != "dos_ratelimit"]
        return modules

    def run(self, progress_callback=None, log_callback=None) -> ScanResult:
        """Run all configured attack modules. Returns ScanResult.

        log_callback(module_name, level, message) is called for live output.
        """
        scan = ScanResult(target_url=self.config.target_url)
        modules = self.get_modules()

        for i, (name, module_class) in enumerate(modules):
            if progress_callback:
                progress_callback(name, i, len(modules))

            start = time.time()
            try:
                module = module_class(self.client, self.config)
                if log_callback:
                    module.set_log_callback(lambda level, msg, _name=module.name: log_callback(_name, level, msg))
                findings = module.run()
                duration = time.time() - start
                result = TestResult(
                    module_name=module.name,
                    category=module.category,
                    findings=findings,
                    tests_run=module.tests_run,
                    tests_passed=module.tests_passed,
                    duration_seconds=duration,
                )
            except Exception as e:
                duration = time.time() - start
                result = TestResult(
                    module_name=module_class.name,
                    category=module_class.category,
                    duration_seconds=duration,
                    error=str(e),
                )
            scan.module_results.append(result)

        scan.scan_end = datetime.now()
        return scan

    def push_results_to_iam(self, scan: ScanResult) -> Tuple[bool, str]:
        """Push scan results to the IAM project's security-testing API."""
        run_id = str(uuid.uuid4())[:8]
        results = []
        for i, finding in enumerate(scan.all_findings):
            results.append({
                "test_id": f"ext_{finding.id}",
                "category": finding.category,
                "name": finding.name,
                "severity": finding.severity.value.lower(),
                "passed": False,
                "details": finding.description,
                "recommendation": finding.recommendation,
            })

        # Also add passed tests as entries
        for module_result in scan.module_results:
            if module_result.tests_passed > 0:
                results.append({
                    "test_id": f"ext_pass_{module_result.category.lower().replace(' ', '_')}",
                    "category": module_result.category,
                    "name": f"{module_result.module_name} - {module_result.tests_passed} checks passed",
                    "severity": "info",
                    "passed": True,
                    "details": f"{module_result.tests_passed} security checks passed in this category.",
                    "recommendation": "",
                })

        try:
            resp = requests.post(
                f"{self.config.target_url}/api/v1/security-testing/import",
                json={"run_id": run_id, "results": results},
                timeout=30,
            )
            if resp.status_code == 200:
                return True, f"Results pushed successfully (run_id: {run_id}, {len(results)} results)"
            else:
                return False, f"Push failed: HTTP {resp.status_code} - {resp.text[:200]}"
        except Exception as e:
            return False, f"Push failed: {e}"
