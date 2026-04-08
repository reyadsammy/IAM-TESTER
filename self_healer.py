"""Self-Healing Security System — automated incident response and remediation."""

import time
import uuid
import re
from datetime import datetime
from typing import List, Optional, Dict, Callable, Tuple

from models import (
    Finding, ScanResult, Severity,
    HealingAction, HealingStatus,
)
from config import ScanConfig
from http_client import SecurityTestClient
from runner import ATTACK_MODULES

_MODULE_MAP = {name: cls for name, cls in ATTACK_MODULES}

# ── Healing Playbooks ──
# Maps (category_pattern, finding_name_pattern) to action templates.
# Each template defines the API call to fix the vulnerability.

PLAYBOOKS: List[Dict] = [
    # ── Authentication ──
    {
        "category": "Authentication",
        "pattern": "default credential",
        "actions": [
            {
                "action_type": "disable_default_creds",
                "description": "Disable default credential accounts and force password change",
                "api_endpoint": "/api/v1/auth/credentials/defaults",
                "api_method": "PUT",
                "api_payload": {"disable_defaults": True, "force_password_change": True},
            },
            {
                "action_type": "rotate_tokens",
                "description": "Invalidate all existing tokens to force re-authentication",
                "api_endpoint": "/api/v1/auth/rotate-tokens",
                "api_method": "POST",
                "api_payload": {"invalidate_existing": True, "reason": "default_credentials_detected"},
            },
        ],
    },
    {
        "category": "Authentication",
        "pattern": "brute.force|credential.stuff",
        "actions": [
            {
                "action_type": "enable_rate_limiting",
                "description": "Enable rate limiting on authentication endpoints",
                "api_endpoint": "/api/v1/config/rate-limiting",
                "api_method": "PUT",
                "api_payload": {"enabled": True, "auth_max_attempts": 5, "lockout_duration": 300},
            },
        ],
    },
    {
        "category": "Authentication",
        "pattern": "token.manipulation|mfa.bypass",
        "actions": [
            {
                "action_type": "rotate_tokens",
                "description": "Rotate all active tokens and enforce re-authentication",
                "api_endpoint": "/api/v1/auth/rotate-tokens",
                "api_method": "POST",
                "api_payload": {"invalidate_existing": True, "reason": "token_manipulation_detected"},
            },
        ],
    },
    # ── Authorization ──
    {
        "category": "Authorization",
        "pattern": "always.allow|authorization.bypass",
        "actions": [
            {
                "action_type": "fix_authorization",
                "description": "Switch authorization to deny-by-default with RBAC enforcement",
                "api_endpoint": "/api/v1/authz/config",
                "api_method": "PUT",
                "api_payload": {"default_deny": True, "require_rbac": True, "audit_all_decisions": True},
            },
        ],
    },
    {
        "category": "Authorization",
        "pattern": "privilege.escalation|idor",
        "actions": [
            {
                "action_type": "fix_authorization",
                "description": "Enforce strict role boundaries and resource ownership checks",
                "api_endpoint": "/api/v1/authz/config",
                "api_method": "PUT",
                "api_payload": {"enforce_ownership": True, "strict_role_boundaries": True},
            },
            {
                "action_type": "isolate_agent",
                "description": "Isolate the test agent used for privilege escalation",
                "api_endpoint": "/api/v1/agents/{agent_id}/isolate",
                "api_method": "POST",
                "api_payload": {"reason": "privilege_escalation_attempt", "initiated_by": "security_scanner"},
            },
        ],
    },
    # ── API Security ──
    {
        "category": "API Security",
        "pattern": "cors|wildcard.origin",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Restrict CORS to specific trusted origins only",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {"cors_origins": [], "cors_allow_credentials": False},
            },
        ],
    },
    {
        "category": "API Security",
        "pattern": "swagger|openapi|documentation.exposure",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Disable public API documentation in production",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {"disable_swagger": True, "disable_redoc": True},
            },
        ],
    },
    {
        "category": "API Security",
        "pattern": "rate.limit",
        "actions": [
            {
                "action_type": "enable_rate_limiting",
                "description": "Enable global rate limiting",
                "api_endpoint": "/api/v1/config/rate-limiting",
                "api_method": "PUT",
                "api_payload": {"enabled": True, "max_requests": 100, "window_seconds": 60},
            },
        ],
    },
    # ── Cryptographic ──
    {
        "category": "Cryptographic",
        "pattern": "default.*key|weak.*key",
        "actions": [
            {
                "action_type": "rotate_keys",
                "description": "Rotate cryptographic signing and encryption keys",
                "api_endpoint": "/api/v1/config/keys",
                "api_method": "PUT",
                "api_payload": {"rotate_secret_key": True, "rotate_encryption_key": True},
            },
            {
                "action_type": "rotate_tokens",
                "description": "Invalidate all tokens signed with the old key",
                "api_endpoint": "/api/v1/auth/rotate-tokens",
                "api_method": "POST",
                "api_payload": {"invalidate_existing": True, "reason": "key_rotation"},
            },
        ],
    },
    # ── Session ──
    {
        "category": "Session",
        "pattern": "session.fixation|session.replay|cross.agent",
        "actions": [
            {
                "action_type": "invalidate_sessions",
                "description": "Invalidate all active sessions and force re-authentication",
                "api_endpoint": "/api/v1/sessions/bulk",
                "api_method": "DELETE",
                "api_payload": {"reason": "security_incident", "invalidate_all": True},
            },
        ],
    },
    {
        "category": "Session",
        "pattern": "session.creation.without.auth|concurrent",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enforce authentication requirement for session creation",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {"require_auth_for_sessions": True, "max_concurrent_sessions": 3},
            },
        ],
    },
    # ── Injection ──
    {
        "category": "Injection",
        "pattern": "sql.injection|command.injection",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enable input sanitization and parameterized query enforcement",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {"input_sanitization": True, "parameterized_queries": True},
            },
            {
                "action_type": "isolate_agent",
                "description": "Isolate the agent used for injection attempts",
                "api_endpoint": "/api/v1/agents/{agent_id}/isolate",
                "api_method": "POST",
                "api_payload": {"reason": "injection_attack_detected", "initiated_by": "security_scanner"},
            },
        ],
    },
    # ── Compliance / Headers ──
    {
        "category": "Compliance",
        "pattern": "security.header|hsts|csp|x-frame",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Apply all recommended security headers",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {
                    "security_headers": {
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff",
                        "X-XSS-Protection": "1; mode=block",
                        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                        "Content-Security-Policy": "default-src 'self'",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                    }
                },
            },
        ],
    },
    # ── Information Disclosure ──
    {
        "category": "Information Disclosure",
        "pattern": "error.message|debug.mode|verbose|exception",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Disable debug mode and verbose error messages in production",
                "api_endpoint": "/api/v1/config/security",
                "api_method": "PUT",
                "api_payload": {"debug_mode": False, "verbose_errors": False, "hide_server_version": True},
            },
        ],
    },
    # ── DoS / Rate Limiting ──
    {
        "category": "DoS / Rate Limiting",
        "pattern": "rate.limit|flood|exhaustion",
        "actions": [
            {
                "action_type": "enable_rate_limiting",
                "description": "Enable aggressive rate limiting and request throttling",
                "api_endpoint": "/api/v1/config/rate-limiting",
                "api_method": "PUT",
                "api_payload": {"enabled": True, "max_requests": 60, "window_seconds": 60, "burst_limit": 20},
            },
        ],
    },
    # ── Store Security ──
    {
        "category": "Store Security",
        "pattern": "sql.injection.*search|product.search",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enable parameterized queries for product search",
                "api_endpoint": "/api/config/security",
                "api_method": "PUT",
                "api_payload": {"parameterized_queries": True, "sanitize_search_input": True},
            },
        ],
    },
    {
        "category": "Store Security",
        "pattern": "idor|cart.*modif|order.*accessible|payment.*accessible",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enable ownership verification on all resource endpoints",
                "api_endpoint": "/api/config/security",
                "api_method": "PUT",
                "api_payload": {"enforce_ownership_checks": True, "verify_resource_ownership": True},
            },
        ],
    },
    {
        "category": "Store Security",
        "pattern": "price.manipulation|payment.*amount|client.controlled",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enable server-side price validation for payments",
                "api_endpoint": "/api/config/security",
                "api_method": "PUT",
                "api_payload": {"server_side_price_validation": True, "reject_zero_negative_amounts": True},
            },
        ],
    },
    {
        "category": "Store Security",
        "pattern": "admin.*without.*role|admin.*accessible",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enforce admin role verification on admin endpoints",
                "api_endpoint": "/api/config/security",
                "api_method": "PUT",
                "api_payload": {"enforce_admin_role": True, "require_jwt_role_claim": True},
            },
        ],
    },
    {
        "category": "Store Security",
        "pattern": "negative.quantity",
        "actions": [
            {
                "action_type": "restore_config",
                "description": "Enable input validation for cart quantities",
                "api_endpoint": "/api/config/security",
                "api_method": "PUT",
                "api_payload": {"validate_quantity_positive": True, "min_quantity": 1},
            },
        ],
    },
]


class SelfHealer:
    """Maps scan findings to remediation API calls and executes them."""

    def __init__(self, client: SecurityTestClient, config: ScanConfig):
        self.client = client
        self.config = config

    def get_actions_for_finding(self, finding: Finding) -> List[HealingAction]:
        """Match a finding against playbooks and return concrete HealingAction instances."""
        actions = []
        finding_text = f"{finding.name} {finding.description}".lower()

        for playbook in PLAYBOOKS:
            # Match category
            if playbook["category"].lower() not in finding.category.lower():
                continue
            # Match pattern
            pattern = playbook["pattern"]
            if not re.search(pattern, finding_text, re.IGNORECASE):
                continue

            for tmpl in playbook["actions"]:
                endpoint = tmpl["api_endpoint"]
                # Adapt endpoint paths for store target (strip /v1 prefix)
                if self.config.target_type == "store" and "/api/v1/" in endpoint:
                    endpoint = endpoint.replace("/api/v1/", "/api/")
                # Replace {agent_id} placeholder
                if "{agent_id}" in endpoint:
                    endpoint = endpoint.replace("{agent_id}", self.config.test_agent_id)

                action = HealingAction(
                    id=str(uuid.uuid4())[:8],
                    finding_id=finding.id,
                    finding_name=finding.name,
                    finding_category=finding.category,
                    finding_severity=finding.severity,
                    action_type=tmpl["action_type"],
                    description=tmpl["description"],
                    api_endpoint=endpoint,
                    api_method=tmpl["api_method"],
                    api_payload=dict(tmpl["api_payload"]),
                )
                actions.append(action)

        return actions

    def get_all_actions(self, scan: ScanResult) -> List[HealingAction]:
        """Get all applicable healing actions for a scan result."""
        actions = []
        seen_types = set()
        for finding in scan.all_findings:
            for action in self.get_actions_for_finding(finding):
                # Deduplicate by (action_type, endpoint)
                key = (action.action_type, action.api_endpoint)
                if key not in seen_types:
                    seen_types.add(key)
                    actions.append(action)
        return actions

    def execute_action(
        self,
        action: HealingAction,
        log_callback: Optional[Callable] = None,
    ) -> HealingAction:
        """Execute a single healing action against the target system."""
        action.status = HealingStatus.IN_PROGRESS
        action.started_at = datetime.now()

        if log_callback:
            log_callback("info", f"Executing: {action.description}")
            log_callback("cmd", f"  {action.api_method} {action.api_endpoint}")

        try:
            method = action.api_method.upper()
            if method == "POST":
                result = self.client.post(action.api_endpoint, json=action.api_payload)
            elif method == "PUT":
                result = self.client.put(action.api_endpoint, json=action.api_payload)
            elif method == "DELETE":
                result = self.client.delete(action.api_endpoint, json=action.api_payload)
            else:
                result = self.client.post(action.api_endpoint, json=action.api_payload)

            action.finished_at = datetime.now()

            if result.error:
                action.status = HealingStatus.FAILED
                action.response_body = result.error
                if log_callback:
                    log_callback("fail", f"  Failed: {result.error}")
            elif result.response:
                action.response_code = result.response.status_code
                action.response_body = result.response.text[:500]

                if result.response.status_code in (200, 201, 204):
                    action.status = HealingStatus.SUCCESS
                    if log_callback:
                        log_callback("success", f"  Success: HTTP {result.response.status_code}")
                elif result.response.status_code == 404:
                    action.status = HealingStatus.FAILED
                    action.response_body = "Endpoint not available on target system"
                    if log_callback:
                        log_callback("warn", f"  Endpoint not available (404)")
                else:
                    action.status = HealingStatus.FAILED
                    if log_callback:
                        log_callback("fail", f"  Failed: HTTP {result.response.status_code}")
            else:
                action.status = HealingStatus.FAILED
                action.response_body = "No response received"
                if log_callback:
                    log_callback("fail", "  Failed: No response")

        except Exception as e:
            action.status = HealingStatus.FAILED
            action.finished_at = datetime.now()
            action.response_body = str(e)
            if log_callback:
                log_callback("fail", f"  Error: {str(e)[:100]}")

        return action

    def execute_all(
        self,
        actions: List[HealingAction],
        log_callback: Optional[Callable] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[HealingAction]:
        """Execute all healing actions sequentially."""
        for i, action in enumerate(actions):
            self.execute_action(action, log_callback)
            if progress_callback:
                progress_callback(i + 1, len(actions))
            time.sleep(0.2)
        return actions

    def verify_action(
        self,
        action: HealingAction,
        finding: Finding,
        log_callback: Optional[Callable] = None,
    ) -> HealingAction:
        """Re-run the original attack to verify the fix worked."""
        if log_callback:
            log_callback("info", f"Verifying fix: {action.description}")

        # Find the module and method that detected this vulnerability
        module_key = self._find_module_for_category(finding.category)
        if not module_key:
            action.verification_result = "Cannot verify: module not found for category"
            return action

        module_cls = _MODULE_MAP.get(module_key)
        if not module_cls:
            action.verification_result = "Cannot verify: module class not found"
            return action

        try:
            module = module_cls(self.client, self.config)
            findings = module.run()

            # Check if the original finding still appears
            still_vulnerable = any(
                f.name == finding.name for f in findings
            )

            if still_vulnerable:
                action.verification_result = "STILL VULNERABLE - Fix did not resolve the issue"
                if log_callback:
                    log_callback("fail", f"  Verification FAILED: vulnerability still present")
            else:
                action.status = HealingStatus.VERIFIED
                action.verification_result = "VERIFIED - Vulnerability no longer detected"
                if log_callback:
                    log_callback("success", f"  Verification PASSED: vulnerability resolved")

        except Exception as e:
            action.verification_result = f"Verification error: {str(e)[:100]}"
            if log_callback:
                log_callback("warn", f"  Verification error: {str(e)[:80]}")

        return action

    def _find_module_for_category(self, category: str) -> Optional[str]:
        """Find the module key that matches a finding category."""
        category_lower = category.lower().replace(" ", "_")
        # Direct match
        if category_lower in _MODULE_MAP:
            return category_lower
        # Fuzzy match
        for key in _MODULE_MAP:
            if key.replace("_", " ") in category.lower() or category.lower() in key.replace("_", " "):
                return key
        return None

    def get_healing_summary(self, actions: List[HealingAction]) -> Dict:
        """Get summary statistics for healing actions."""
        return {
            "total": len(actions),
            "pending": sum(1 for a in actions if a.status == HealingStatus.PENDING),
            "in_progress": sum(1 for a in actions if a.status == HealingStatus.IN_PROGRESS),
            "success": sum(1 for a in actions if a.status == HealingStatus.SUCCESS),
            "failed": sum(1 for a in actions if a.status == HealingStatus.FAILED),
            "verified": sum(1 for a in actions if a.status == HealingStatus.VERIFIED),
        }
