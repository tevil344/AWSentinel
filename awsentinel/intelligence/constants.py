from enum import StrEnum


class IntelligenceSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationDecision(StrEnum):
    SAFE_AUTO = "SAFE_AUTO"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    BLOCKED = "BLOCKED"
    DEFERRED = "DEFERRED"


DEFAULT_INACTIVITY_DAYS = 90
STALE_ATTACK_PATH_DAYS = 365
