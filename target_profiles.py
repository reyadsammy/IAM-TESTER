"""Target profiles — endpoint maps and payload builders for different target systems."""

from typing import Optional, Dict, Any


# Endpoint maps for each target type
PROFILES = {
    "iam": {
        "name": "Agentic IAM",
        "login": "/api/v1/auth/login",
        "logout": "/api/v1/auth/logout",
        "mfa_verify": "/api/v1/auth/mfa/verify",
        "auth_methods": "/api/v1/auth/methods",
        "authorize": "/api/v1/authz/authorize",
        "sessions": "/api/v1/sessions/",
        "session_detail": "/api/v1/sessions/{id}",
        "sessions_stats": "/api/v1/sessions/stats/summary",
        "sessions_cleanup": "/api/v1/sessions/cleanup",
        "sessions_terminate": "/api/v1/sessions/terminate",
        "audit_events": "/api/v1/audit/events",
        "audit_event_detail": "/api/v1/audit/events/{id}",
        "audit_query": "/api/v1/audit/events/query",
        "audit_stats": "/api/v1/audit/statistics",
        "audit_integrity": "/api/v1/audit/integrity/verify",
        "intelligence_anomalies": "/api/v1/intelligence/anomalies",
        "intelligence_analyze": "/api/v1/intelligence/analyze",
        "intelligence_stats": "/api/v1/intelligence/statistics",
        "trust_score_update": "/api/v1/intelligence/trust-score/update",
        "trust_score": "/api/v1/intelligence/trust-score/{agent_id}",
        "models_retrain": "/api/v1/intelligence/models/retrain",
        "models_status": "/api/v1/intelligence/models/status",
        "api_root": "/api/v1",
        "root": "/",
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
        "graphql": "/graphql",
        # Store-specific (not available in IAM)
        "products": None,
        "product_detail": None,
        "categories": None,
        "cart": None,
        "cart_item": None,
        "orders": None,
        "order_detail": None,
        "order_cancel": None,
        "payments_process": None,
        "payment_detail": None,
        "admin_stats": None,
        "admin_orders": None,
        "admin_order_status": None,
        "admin_products": None,
        "admin_users": None,
        "register": None,
        "profile": None,
        "health": None,
    },
    "store": {
        "name": "IAM Store",
        "login": "/api/auth/login",
        "logout": "/api/auth/logout",
        "register": "/api/auth/register",
        "profile": "/api/auth/me",
        "health": "/store/health",
        "root": "/",
        "api_root": "/",
        "docs": "/docs",
        "redoc": "/redoc",
        "openapi": "/openapi.json",
        "graphql": None,
        # Store endpoints
        "products": "/api/products",
        "product_detail": "/api/products/{id}",
        "categories": "/api/products/categories",
        "cart": "/api/cart",
        "cart_item": "/api/cart/{id}",
        "orders": "/api/orders",
        "order_detail": "/api/orders/{id}",
        "order_cancel": "/api/orders/{id}/cancel",
        "payments_process": "/api/payments/process",
        "payment_detail": "/api/payments/{id}",
        "admin_stats": "/api/admin/stats",
        "admin_orders": "/api/admin/orders",
        "admin_order_status": "/api/admin/orders/{id}/status",
        "admin_products": "/api/admin/products",
        "admin_users": "/api/admin/users",
        # IAM-specific (not directly available in store)
        "mfa_verify": None,
        "auth_methods": None,
        "authorize": None,
        "sessions": None,
        "session_detail": None,
        "sessions_stats": None,
        "sessions_cleanup": None,
        "sessions_terminate": None,
        "audit_events": None,
        "audit_event_detail": None,
        "audit_query": None,
        "audit_stats": None,
        "audit_integrity": None,
        "intelligence_anomalies": None,
        "intelligence_analyze": None,
        "intelligence_stats": None,
        "trust_score_update": None,
        "trust_score": None,
        "models_retrain": None,
        "models_status": None,
    },
}

TARGET_TYPES = list(PROFILES.keys())
TARGET_LABELS = {k: v["name"] for k, v in PROFILES.items()}


def get_endpoint(target_type: str, key: str, **kwargs) -> Optional[str]:
    """Get endpoint path for a given target type and key.

    Returns None if the endpoint doesn't exist for this target type.
    kwargs are used for path parameter substitution (e.g., id=123).
    """
    profile = PROFILES.get(target_type, PROFILES["iam"])
    path = profile.get(key)
    if path is None:
        return None
    if kwargs:
        path = path.format(**kwargs)
    return path


def build_login_payload(target_type: str, username: str, password: str, agent_id: str = "") -> Dict[str, Any]:
    """Build the correct login request body for the target type."""
    if target_type == "store":
        return {"username": username, "password": password}
    else:
        return {
            "agent_id": agent_id or f"agent_{username}",
            "method": "password",
            "credentials": {"username": username, "password": password},
        }


def build_register_payload(target_type: str, username: str, password: str, **kwargs) -> Optional[Dict[str, Any]]:
    """Build a registration payload for the target type."""
    if target_type == "store":
        return {
            "username": username,
            "display_name": kwargs.get("display_name", username),
            "password": password,
        }
    return None


def get_protected_endpoints(target_type: str):
    """Get list of (method, path) tuples for endpoints that should require auth."""
    if target_type == "store":
        return [
            ("GET", "/api/cart"),
            ("GET", "/api/orders"),
            ("GET", "/api/auth/me"),
            ("POST", "/api/cart"),
            ("POST", "/api/orders"),
            ("POST", "/api/payments/process"),
        ]
    else:
        return [
            ("GET", "/api/v1/sessions/"),
            ("GET", "/api/v1/audit/events"),
            ("GET", "/api/v1/audit/statistics"),
            ("GET", "/api/v1/intelligence/anomalies"),
            ("GET", "/api/v1/sessions/stats/summary"),
            ("POST", "/api/v1/sessions/"),
            ("POST", "/api/v1/audit/events/query"),
            ("POST", "/api/v1/intelligence/analyze"),
        ]


def get_admin_endpoints(target_type: str):
    """Get list of (method, path) tuples for admin-only endpoints."""
    if target_type == "store":
        return [
            ("GET", "/api/admin/stats"),
            ("GET", "/api/admin/orders"),
            ("GET", "/api/admin/products"),
            ("GET", "/api/admin/users"),
        ]
    else:
        return [
            ("POST", "/api/v1/sessions/cleanup"),
            ("POST", "/api/v1/sessions/terminate"),
            ("POST", "/api/v1/audit/integrity/verify"),
            ("POST", "/api/v1/intelligence/models/retrain"),
            ("GET", "/api/v1/intelligence/models/status"),
        ]
