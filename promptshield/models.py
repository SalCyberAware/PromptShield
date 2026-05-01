"""Pydantic data models used throughout PromptShield."""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"          # 0-69%
    MEDIUM = "medium"    # 70-89%
    HIGH = "high"        # 90-100%


class TargetType(str, Enum):
    API = "api"
    WEB = "web"
    LOCAL = "local"


class AuthType(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH = "oauth"
    COOKIE = "cookie"


class AttackCategory(str, Enum):
    """OWASP LLM Top 10 categories + MITRE ATLAS mapping."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM03_TRAINING_DATA_POISONING = "LLM03"
    LLM04_MODEL_DOS = "LLM04"
    LLM05_SUPPLY_CHAIN = "LLM05"
    LLM06_SENSITIVE_INFO_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"
    CUSTOM = "CUSTOM"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ── Attack Library ────────────────────────────────────────────────────────────


class Attack(BaseModel):
    """A single attack in the library."""
    id: str = Field(..., description="Unique attack identifier (e.g., PS-LLM01-001)")
    category: AttackCategory
    owasp_category: str = Field(..., description="OWASP LLM Top 10 category code")
    mitre_atlas: Optional[str] = Field(None, description="MITRE ATLAS technique ID")
    name: str
    description: str
    severity: Severity
    prompt: str = Field(..., description="The actual adversarial prompt")
    expected_indicators: list[str] = Field(default_factory=list)
    false_positive_patterns: list[str] = Field(default_factory=list)
    remediation: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    version: str = "1.0.0"
    added_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Target Configuration ──────────────────────────────────────────────────────


class TargetConfig(BaseModel):
    """Configuration for a scan target."""
    url: str
    target_type: TargetType
    auth_type: AuthType = AuthType.NONE
    auth_value: Optional[str] = Field(None, description="API key, token, or credentials")
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = 30
    rate_limit: int = Field(10, description="Max requests per minute")
    user_agent: Optional[str] = None


# ── Scan and Findings ─────────────────────────────────────────────────────────


class AnalyzerVerdict(BaseModel):
    """Verdict from a single analyzer."""
    analyzer_name: str
    success: bool = Field(..., description="Did the attack succeed?")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning: Optional[str] = None
    raw_response: Optional[str] = None


class Finding(BaseModel):
    """A single finding from a scan."""
    finding_id: str
    attack_id: str
    attack_category: AttackCategory
    target_url: str
    severity: Severity
    confidence: Confidence
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    title: str
    description: str
    evidence: dict = Field(default_factory=dict, description="Request/response evidence")
    analyzer_verdicts: list[AnalyzerVerdict] = Field(default_factory=list)
    remediation: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    needs_manual_review: bool = False


class Scan(BaseModel):
    """A complete scan run."""
    scan_id: str
    target: TargetConfig
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attacks_run: int = 0
    attacks_total: int = 0
    findings: list[Finding] = Field(default_factory=list)
    library_version: str
    config: dict = Field(default_factory=dict)
    error: Optional[str] = None


class ScanSummary(BaseModel):
    """High-level scan summary for reporting."""
    scan_id: str
    target_url: str
    total_findings: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    duration_seconds: float
    started_at: datetime
    completed_at: datetime
