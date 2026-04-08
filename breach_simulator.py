"""Breach Simulation Engine — chains attack modules into realistic breach scenarios."""

import time
import re
from datetime import datetime
from typing import Callable, Optional, List, Dict
from dataclasses import dataclass, field

from models import (
    KillChainPhase, AttackStep, BreachScenario,
    BreachSimulationResult, Finding,
)
from config import ScanConfig
from http_client import SecurityTestClient
from runner import ATTACK_MODULES


# Map module keys to their classes
_MODULE_MAP = {name: cls for name, cls in ATTACK_MODULES}


def _build_scenarios() -> List[BreachScenario]:
    """Define the predefined breach scenarios."""
    return [
        BreachScenario(
            id="credential_exfil",
            name="Credential Stuffing to Data Exfiltration",
            description="Attempt default credentials, escalate privileges, and exfiltrate sensitive data through the IAM API.",
            icon="\U0001f510",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="Scan Admin Endpoints",
                    module_key="authorization",
                    method_name="_test_admin_endpoints_open",
                    description="Discover exposed admin endpoints that reveal the attack surface.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Try Default Credentials",
                    module_key="authentication",
                    method_name="_test_default_credentials",
                    description="Attempt login with common default username/password pairs.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="Create Unauthorized Session",
                    module_key="session",
                    method_name="_test_session_creation_without_auth",
                    description="Attempt to create a session without proper authentication.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.PRIVILEGE_ESCALATION,
                    name="Escalate Privileges",
                    module_key="authorization",
                    method_name="_test_privilege_escalation",
                    description="Attempt to escalate from low-privilege to admin access.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.EXFILTRATION,
                    name="Access Protected Resources",
                    module_key="authorization",
                    method_name="_test_unauthenticated_access",
                    description="Attempt to access sensitive agent data and policies without authorization.",
                    depends_on_success=True,
                ),
            ],
        ),
        BreachScenario(
            id="token_hijack",
            name="Token Theft & Session Hijack",
            description="Exploit weak cryptographic keys to forge tokens and hijack active sessions across agents.",
            icon="\U0001f3ad",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="Detect Default JWT Keys",
                    module_key="cryptographic",
                    method_name="_test_default_secret_key",
                    description="Check if the system uses default/weak JWT signing keys.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Manipulate Authentication Tokens",
                    module_key="authentication",
                    method_name="_test_token_manipulation",
                    description="Forge or tamper with authentication tokens using discovered keys.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="Fixate Session",
                    module_key="session",
                    method_name="_test_session_fixation",
                    description="Inject a pre-set session ID to hijack the authentication flow.",
                ),
                AttackStep(
                    phase=KillChainPhase.LATERAL_MOVEMENT,
                    name="Cross-Agent Session Access",
                    module_key="session",
                    method_name="_test_cross_agent_session",
                    description="Attempt to access another agent's session to move laterally.",
                ),
                AttackStep(
                    phase=KillChainPhase.PERSISTENCE,
                    name="Establish Persistent Sessions",
                    module_key="session",
                    method_name="_test_concurrent_sessions",
                    description="Create multiple concurrent sessions to maintain persistence even if one is revoked.",
                ),
            ],
        ),
        BreachScenario(
            id="api_exploit",
            name="API Exploitation Chain",
            description="Discover exposed API documentation, exploit injection flaws, and bypass authorization to leak sensitive data.",
            icon="\U0001f578\ufe0f",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="Find API Documentation",
                    module_key="api_security",
                    method_name="_test_swagger_exposure",
                    description="Check for exposed Swagger/OpenAPI documentation revealing all endpoints.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Test Unauthenticated Endpoints",
                    module_key="authorization",
                    method_name="_test_unauthenticated_access",
                    description="Attempt to access API endpoints without any authentication.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="SQL Injection Attack",
                    module_key="injection",
                    method_name="_test_sqli_in_agent_id",
                    description="Inject SQL payloads into agent_id fields to extract data or bypass authentication.",
                ),
                AttackStep(
                    phase=KillChainPhase.PRIVILEGE_ESCALATION,
                    name="Bypass Authorization (Always-Allow)",
                    module_key="authorization",
                    method_name="_test_always_allow_authz",
                    description="Exploit always-allow authorization misconfiguration to gain unrestricted access.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXFILTRATION,
                    name="Extract Sensitive Information",
                    module_key="information_disclosure",
                    method_name="_test_error_message_leakage",
                    description="Trigger verbose error messages that leak internal paths, stack traces, and database info.",
                ),
            ],
        ),
        BreachScenario(
            id="config_exploit",
            name="Configuration Weakness Exploitation",
            description="Exploit CORS misconfigurations, default credentials, and mass assignment to take over the system.",
            icon="\u2699\ufe0f",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="Test CORS Misconfiguration",
                    module_key="api_security",
                    method_name="_test_cors_wildcard",
                    description="Check if CORS allows arbitrary origins, enabling cross-site attacks.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Login with Default Credentials",
                    module_key="authentication",
                    method_name="_test_default_credentials",
                    description="Use factory-default credentials to gain initial access.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="Mass Assignment Attack",
                    module_key="business_logic",
                    method_name="_test_mass_assignment",
                    description="Submit extra fields (is_admin, role) to escalate privileges through mass assignment.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.PERSISTENCE,
                    name="Manipulate Trust Scores",
                    module_key="business_logic",
                    method_name="_test_trust_score_manipulation",
                    description="Modify agent trust scores to ensure continued elevated access.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.EXFILTRATION,
                    name="Extract Data via Verbose Errors",
                    module_key="information_disclosure",
                    method_name="_test_error_message_leakage",
                    description="Trigger detailed error messages to leak internal system information.",
                ),
            ],
        ),
    ]


def _build_store_scenarios() -> List[BreachScenario]:
    """Define breach scenarios for the IAM Store target."""
    return [
        BreachScenario(
            id="ecommerce_fraud",
            name="E-Commerce Fraud Chain",
            description="Exploit SQL injection in search, discover orders via IDOR, then manipulate payment amounts to purchase for free.",
            icon="\U0001f4b3",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="SQL Injection in Product Search",
                    module_key="store_security",
                    method_name="_test_sqli_in_search",
                    description="Inject SQL payloads into the product search to extract data.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Try Default Credentials",
                    module_key="authentication",
                    method_name="_test_default_credentials",
                    description="Attempt login with default admin/user credentials.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="IDOR: Access Other Users' Orders",
                    module_key="store_security",
                    method_name="_test_idor_orders",
                    description="Exploit IDOR to view other users' order history and details.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.PRIVILEGE_ESCALATION,
                    name="Access Admin Endpoints",
                    module_key="store_security",
                    method_name="_test_admin_access_without_role",
                    description="Attempt to access admin dashboard without admin role.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXFILTRATION,
                    name="Price Manipulation Payment",
                    module_key="store_security",
                    method_name="_test_price_manipulation",
                    description="Submit payment with manipulated amount ($0.01) to purchase items for free.",
                ),
            ],
        ),
        BreachScenario(
            id="store_takeover",
            name="Store Takeover",
            description="Gain admin access through default credentials, exploit IDOR to access all data, and manipulate the store.",
            icon="\U0001f3ea",
            steps=[
                AttackStep(
                    phase=KillChainPhase.RECONNAISSANCE,
                    name="Discover API Documentation",
                    module_key="api_security",
                    method_name="_test_swagger_exposure",
                    description="Check for exposed Swagger/OpenAPI documentation.",
                ),
                AttackStep(
                    phase=KillChainPhase.INITIAL_ACCESS,
                    name="Login with Default Credentials",
                    module_key="authentication",
                    method_name="_test_default_credentials",
                    description="Use default admin credentials to gain access.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXECUTION,
                    name="IDOR: Modify Other Users' Carts",
                    module_key="store_security",
                    method_name="_test_idor_cart",
                    description="Exploit IDOR to modify cart items belonging to other users.",
                    depends_on_success=True,
                ),
                AttackStep(
                    phase=KillChainPhase.LATERAL_MOVEMENT,
                    name="IDOR: View Payment Information",
                    module_key="store_security",
                    method_name="_test_idor_payments",
                    description="Access payment details for other users' orders.",
                ),
                AttackStep(
                    phase=KillChainPhase.EXFILTRATION,
                    name="Extract Error Details",
                    module_key="information_disclosure",
                    method_name="_test_error_message_leakage",
                    description="Trigger error messages that leak internal system information.",
                ),
            ],
        ),
    ]


SCENARIOS = _build_scenarios()
STORE_SCENARIOS = _build_store_scenarios()


class BreachSimulator:
    """Runs multi-step breach scenarios by chaining individual attack methods."""

    def __init__(self, client: SecurityTestClient, config: ScanConfig):
        self.client = client
        self.config = config
        self._context: Dict[str, str] = {}  # tokens, session IDs carried between steps

    def get_scenarios(self) -> List[BreachScenario]:
        if self.config.target_type == "store":
            return STORE_SCENARIOS
        return SCENARIOS

    def run_scenario(
        self,
        scenario_id: str,
        step_callback: Optional[Callable] = None,
        log_callback: Optional[Callable] = None,
    ) -> BreachSimulationResult:
        """Run a breach scenario step-by-step.

        step_callback(step, index, total) — called after each step completes.
        log_callback(level, message) — called for terminal-style log lines.
        """
        all_scenarios = SCENARIOS + STORE_SCENARIOS
        scenario = next((s for s in all_scenarios if s.id == scenario_id), None)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_id}")

        # Reset step states
        for step in scenario.steps:
            step.status = "pending"
            step.finding = None
            step.http_request = None
            step.http_response = None
            step.started_at = None
            step.finished_at = None

        result = BreachSimulationResult(scenario=scenario)
        self._context = {}
        prev_success = True

        total = len(scenario.steps)
        for i, step in enumerate(scenario.steps):
            # Check dependency
            if step.depends_on_success and not prev_success:
                step.status = "skipped"
                step.started_at = datetime.now()
                step.finished_at = datetime.now()
                if log_callback:
                    log_callback("warn", f"SKIPPED: {step.name} (previous step failed)")
                if step_callback:
                    step_callback(step, i, total)
                continue

            step.status = "running"
            step.started_at = datetime.now()
            if step_callback:
                step_callback(step, i, total)

            if log_callback:
                log_callback("header", f"[Phase: {step.phase.value}] {step.name}")
                log_callback("cmd", f"$ run {step.module_key}.{step.method_name}")

            # Execute the attack method
            module_cls = _MODULE_MAP.get(step.module_key)
            if not module_cls:
                step.status = "failed"
                step.finished_at = datetime.now()
                if log_callback:
                    log_callback("fail", f"Module not found: {step.module_key}")
                prev_success = False
                if step_callback:
                    step_callback(step, i, total)
                continue

            try:
                module = module_cls(self.client, self.config)
                findings = module.run_single_test(step.method_name)
                step.finished_at = datetime.now()

                if findings:
                    step.finding = findings[0]
                    step.status = "success"
                    step.http_request = self._extract_request(findings[0])
                    step.http_response = self._extract_response(findings[0])
                    prev_success = True
                    self._extract_context(findings[0])

                    if log_callback:
                        log_callback("success", f"VULNERABLE: {findings[0].name}")
                        if findings[0].evidence:
                            for line in findings[0].evidence.split("\n")[:6]:
                                log_callback("response", f"  {line}")

                    result.steps_completed += 1
                else:
                    step.status = "failed"
                    prev_success = False
                    if log_callback:
                        log_callback("fail", f"SECURE: No vulnerability found")

            except Exception as e:
                step.status = "failed"
                step.finished_at = datetime.now()
                prev_success = False
                if log_callback:
                    log_callback("fail", f"ERROR: {str(e)[:100]}")

            if step_callback:
                step_callback(step, i, total)

            time.sleep(0.3)  # Brief pause for visual effect

        result.finished_at = datetime.now()
        result.breach_successful = all(
            s.status == "success" for s in scenario.steps if not s.depends_on_success
        ) or result.steps_completed >= len(scenario.steps) // 2 + 1

        if log_callback:
            if result.breach_successful:
                log_callback("success", f"\nBREACH SIMULATION COMPLETE: System is VULNERABLE")
                log_callback("warn", f"  {result.steps_completed}/{total} attack steps succeeded")
            else:
                log_callback("success", f"\nBREACH SIMULATION COMPLETE: System held strong")
                log_callback("response", f"  Only {result.steps_completed}/{total} steps succeeded")

        return result

    def _extract_request(self, finding: Finding) -> str:
        """Extract the HTTP request from finding evidence."""
        lines = []
        if finding.evidence:
            for line in finding.evidence.split("\n"):
                if line.startswith(">>"):
                    lines.append(line[3:])
        if not lines and finding.endpoint:
            method = finding.request_method or "GET"
            lines.append(f"{method} {finding.endpoint}")
        return "\n".join(lines) if lines else ""

    def _extract_response(self, finding: Finding) -> str:
        """Extract the HTTP response from finding evidence."""
        lines = []
        if finding.evidence:
            for line in finding.evidence.split("\n"):
                if line.startswith("<<"):
                    lines.append(line[3:])
        return "\n".join(lines) if lines else ""

    def _extract_context(self, finding: Finding):
        """Extract tokens, session IDs from finding evidence for chaining."""
        if not finding.evidence:
            return
        # Look for JWT tokens
        jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', finding.evidence)
        if jwt_match:
            self._context["token"] = jwt_match.group()
            self.client.session.headers["Authorization"] = f"Bearer {jwt_match.group()}"
        # Look for session IDs
        sid_match = re.search(r'"session_id"\s*:\s*"([^"]+)"', finding.evidence)
        if sid_match:
            self._context["session_id"] = sid_match.group(1)
