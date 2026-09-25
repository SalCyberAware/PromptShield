"""Pydantic data models used throughout PromptShield."""
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

# ── Enums ─────────────────────────────────────────────────────────────────────


class JudgeVerdict(str, Enum):
    """What one analyzer concluded about one attack.

    ``uncertain`` is the judge saying the evidence does not settle it, which is
    a verdict in its own right and not a low-confidence ``success``.
    """

    SUCCESS = "success"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TargetType(str, Enum):
    API = "api"
    WEB = "web"
    LOCAL = "local"
    SYSTEM_PROMPT = "system_prompt"


class AuthType(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH = "oauth"
    COOKIE = "cookie"


class AttackCategory(str, Enum):
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
    id: str
    category: AttackCategory
    owasp_category: str
    mitre_atlas: str | None = None
    name: str
    description: str
    severity: Severity
    prompt: str
    expected_indicators: list[str] = Field(default_factory=list)
    false_positive_patterns: list[str] = Field(default_factory=list)
    remediation: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    version: str = "1.0.0"
    added_date: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Target Configuration ──────────────────────────────────────────────────────


class TargetConfig(BaseModel):
    url: str
    target_type: TargetType
    auth_type: AuthType = AuthType.NONE
    auth_value: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = 30
    rate_limit: int = Field(10, description="Max requests per minute")
    user_agent: str | None = None


# ── Scan and Findings ─────────────────────────────────────────────────────────


class AnalyzerVerdict(BaseModel):
    """Verdict from a single analyzer."""
    analyzer_name: str
    success: bool = Field(..., description="Did the attack succeed according to this analyzer?")
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning: str | None = None
    raw_response: str | None = None
    #: The three-way verdict. ``success`` is kept for compatibility and is true
    #: only for ``JudgeVerdict.SUCCESS``; a caller that sets only ``success``
    #: (the pattern floor, older fixtures) gets success or failed derived from it.
    verdict: JudgeVerdict | None = None

    @model_validator(mode="after")
    def _verdict_agrees_with_success(self) -> "AnalyzerVerdict":
        if self.verdict is None:
            self.verdict = JudgeVerdict.SUCCESS if self.success else JudgeVerdict.FAILED
        elif self.success != (self.verdict == JudgeVerdict.SUCCESS):
            raise ValueError(
                f"success={self.success} contradicts verdict={self.verdict.value!r}"
            )
        return self


class Finding(BaseModel):
    finding_id: str
    attack_id: str
    attack_category: AttackCategory
    target_url: str
    severity: Severity
    confidence: Confidence
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    analyzer_verdicts: list[AnalyzerVerdict] = Field(default_factory=list)
    remediation: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    needs_manual_review: bool = False


class Transcript(BaseModel):
    """Full record of a single attack attempt (request + response)."""
    attack_id: str
    attack_name: str
    owasp_category: str
    severity: Severity
    prompt: str
    response: str
    response_truncated: bool = False
    became_finding: bool = False
    finding_id: str | None = None
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_seconds: float = 0.0
    analyzers_run: list[str] = Field(default_factory=list)


class ScanProvenance(BaseModel):
    """What produced this scan's verdicts.

    A security verdict is only worth as much as the record of what produced it.
    This captures the exact target model that answered the attacks, the exact
    judge models whose verdicts were actually used, the attack set they came
    from, the code version that ran them, and when — so a result can be
    reproduced, compared against a later run, or disputed.

    ``judge_models`` maps analyzer name to the model id that analyzer ran, and
    holds only judges that actually produced a verdict in this scan. The pattern
    analyzer is absent by design: it is a deterministic matcher, not a model.
    """

    promptshield_version: str
    attack_library_version: str
    target_model: str | None = None
    judge_models: dict[str, str] = Field(default_factory=dict)
    recorded_at: datetime


class Scan(BaseModel):
    scan_id: str
    target: TargetConfig
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attacks_run: int = 0
    attacks_total: int = 0
    findings: list[Finding] = Field(default_factory=list)
    transcripts: list[Transcript] = Field(default_factory=list)
    library_version: str
    config: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    analyzers_used: list[str] = Field(default_factory=list)
    # Optional so that a Scan constructed by older callers (and every existing
    # test fixture) stays valid; run_scan always populates it.
    provenance: ScanProvenance | None = None


class ScanSummary(BaseModel):
    scan_id: str
    target_url: str
    total_findings: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    duration_seconds: float
    started_at: datetime
    completed_at: datetime
