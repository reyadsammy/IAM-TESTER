"""Configuration for the IAM Security Tester."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class ScanConfig:
    target_url: str = "http://localhost:8000"
    timeout: int = 10
    max_retries: int = 2
    verify_ssl: bool = False
    default_credentials: List[Dict[str, str]] = field(default_factory=lambda: [
        {"username": "admin", "password": "admin123"},
        {"username": "user", "password": "user123"},
        {"username": "operator", "password": "operator123"},
    ])
    test_agent_id: str = "agent_security_scanner"
    concurrent_requests: int = 10
    dos_request_count: int = 100
    output_dir: str = "./reports"
    categories: Optional[List[str]] = None
    skip_dos: bool = False
    verbose: bool = False

    # Known default keys from the target system
    default_secret_key: str = "your-secret-key-change-in-production"
    default_encryption_key: str = "your-encryption-key-32-chars-long!"
