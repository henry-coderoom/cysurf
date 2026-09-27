"""Shared data structures for Cysurf's checks."""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    check_id: str
    category: str
    severity: Severity
    title: str
    detail: str
    remediation: str = ""
    passed: bool = False