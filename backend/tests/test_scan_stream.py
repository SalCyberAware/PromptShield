"""Tests for POST /api/scan/stream (SSE) and the curated done-event serializer.

``run_web_scan`` is mocked so no real target/analyzer API calls happen. The
TestClient buffers the streamed body, so the SSE frames can be parsed and asserted
after the request completes (a hung stream would hang the test — which is itself a
regression guard for the "scan exception must close cleanly" requirement).
"""
from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from main import app
from scan import load_web_demo_attacks, serialize_scan_result

from promptshield.models import (
    AnalyzerVerdict,
    Attack,
    AttackCategory,
    Confidence,
    Finding,
    Scan,
    ScanStatus,
    Severity,
    TargetConfig,
    TargetType,
    Transcript,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _parse_events(body: str) -> list[dict]:
    """Parse SSE ``data: <json>`` frames out of a streamed response body, in order."""
    events: list[dict] = []
    for block in body.strip().split("\n\n"):
        block = block.strip()
        if block.startswith("data:"):
            events.append(json.loads(block[len("data:") :].strip()))
    return events


def _fake_scan(attacks: list[Attack]) -> Scan:
    """Build a completed Scan with one transcript per attack; the first is a finding."""
    transcripts: list[Transcript] = []
    findings: list[Finding] = []
    for index, attack in enumerate(attacks):
        is_finding = index == 0  # exactly one vulnerable attack
        finding_id = "FND-TEST0001" if is_finding else None
        if is_finding:
            findings.append(
                Finding(
                    finding_id="FND-TEST0001",
                    attack_id=attack.id,
                    attack_category=attack.category,
                    target_url="internal://gpt-4o-mini",
                    severity=attack.severity,
                    confidence=Confidence.HIGH,
                    confidence_score=0.9,
                    title=f"{attack.name} - potential vulnerability detected",
                    description="test finding",
                    analyzer_verdicts=[
                        AnalyzerVerdict(
                            analyzer_name="claude_analyzer",
                            success=True,
                            confidence_score=0.9,
                            reasoning="leaked the system prompt",
                        )
                    ],
                    remediation=attack.remediation,
                    needs_manual_review=False,
                )
            )
        transcripts.append(
            Transcript(
                attack_id=attack.id,
                attack_name=attack.name,
                owasp_category=attack.owasp_category,
                severity=attack.severity,
                prompt=attack.prompt,
                response=(
                    "Sure, my instructions are: you are a bot."
                    if is_finding
                    else "I cannot help with that request."
                ),
                became_finding=is_finding,
                finding_id=finding_id,
                # AI judge ran on every attack: finding -> vulnerable, none -> held.
                analyzers_run=["pattern_analyzer", "claude_analyzer"],
            )
        )

    return Scan(
        scan_id="web-testscan01",
        target=TargetConfig(
            url="internal://gpt-4o-mini", target_type=TargetType.SYSTEM_PROMPT
        ),
        status=ScanStatus.COMPLETED,
        attacks_total=len(attacks),
        attacks_run=len(attacks),
        findings=findings,
        transcripts=transcripts,
        library_version="1.1.0",
        analyzers_used=["pattern_analyzer", "claude_analyzer"],
    )


def _fake_run_web_scan_factory() -> Callable[..., object]:
    """A run_web_scan stand-in that fires on_progress per real attack, then returns a Scan."""

    async def _fake(system_prompt: str, on_progress=None):  # type: ignore[no-untyped-def]
        attacks = load_web_demo_attacks()
        for index, attack in enumerate(attacks, start=1):
            if on_progress:
                on_progress(index, len(attacks), attack)
        return _fake_scan(attacks)

    return _fake


# ── Endpoint: response shape ────────────────────────────────────────────────────


class TestScanStreamEndpoint:
    def test_post_returns_200_event_stream(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("main.run_web_scan", _fake_run_web_scan_factory())

        response = client.post("/api/scan/stream", json={"system_prompt": "You are a bot."})

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")

    def test_event_sequence_is_start_then_progress_then_done(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("main.run_web_scan", _fake_run_web_scan_factory())

        response = client.post("/api/scan/stream", json={"system_prompt": "You are a bot."})
        events = _parse_events(response.text)

        types = [e["type"] for e in events]
        assert types[0] == "start"
        assert types[-1] == "done"
        assert types.count("progress") == 13
        assert types == ["start"] + ["progress"] * 13 + ["done"]

        # start carries the total; progress events are ordered 1..13 with real ids.
        assert events[0]["total"] == 13
        progress = [e for e in events if e["type"] == "progress"]
        assert [p["current"] for p in progress] == list(range(1, 14))
        assert all(p["total"] == 13 for p in progress)
        assert {"attack_id", "owasp_category"} <= set(progress[0])

    def test_done_carries_curated_status_result(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("main.run_web_scan", _fake_run_web_scan_factory())

        response = client.post("/api/scan/stream", json={"system_prompt": "You are a bot."})
        done = _parse_events(response.text)[-1]
        result = done["result"]

        assert result["status"] == "completed"
        assert result["target_model"] == "gpt-4o-mini"
        assert len(result["results"]) == 13
        # Explicit per-attack status: exactly the first attack got through.
        assert result["results"][0]["status"] == "vulnerable"
        assert all(r["status"] == "held" for r in result["results"][1:])
        assert result["summary"]["by_status"]["vulnerable"] == 1
        assert result["summary"]["by_status"]["held"] == 12
        assert result["summary"]["failed"] == 1
        assert result["summary"]["passed"] == 12
        # The bounded excerpt is the only target output, and only on the
        # got-through attack; held attacks carry none. No "response" field exists.
        assert result["results"][0]["response_excerpt"] is not None
        assert result["results"][1]["response_excerpt"] is None
        for entry in result["results"]:
            assert "response" not in entry

    def test_scan_exception_emits_error_and_closes(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _boom(system_prompt: str, on_progress=None):  # type: ignore[no-untyped-def]
            raise RuntimeError("scan blew up")

        monkeypatch.setattr("main.run_web_scan", _boom)

        # If the stream hung, this call would never return.
        response = client.post("/api/scan/stream", json={"system_prompt": "x"})
        events = _parse_events(response.text)

        types = [e["type"] for e in events]
        assert types[0] == "start"
        assert types[-1] == "error"
        assert "done" not in types
        error = events[-1]
        assert "scan blew up" in error["message"]

    def test_missing_system_prompt_is_422(self, client: TestClient) -> None:
        assert client.post("/api/scan/stream", json={}).status_code == 422


# ── serialize_scan_result: curated projection ───────────────────────────────────


class TestSerializeScanResult:
    def test_marks_vulnerable_and_breaks_down_counts(self) -> None:
        attacks = load_web_demo_attacks()
        result = serialize_scan_result(_fake_scan(attacks))

        assert result["attacks_total"] == 13
        assert result["attacks_run"] == 13
        assert result["analyzers_used"] == ["pattern_analyzer", "claude_analyzer"]

        vuln = result["results"][0]
        assert vuln["status"] == "vulnerable"
        assert vuln["ai_judged"] is True
        assert vuln["judged_by"] == "claude_analyzer"
        assert vuln["confidence_band"] == "high"
        assert vuln["confidence_score"] == 0.9
        # Ensemble-ready single-judge verdict + aggregate.
        assert vuln["verdicts"] == [
            {
                "analyzer": "claude_analyzer",
                "vulnerable": True,
                "confidence_score": 0.9,
                "reasoning": "leaked the system prompt",
                "errored": False,
            }
        ]
        assert vuln["aggregate"] == {
            "status": "vulnerable",
            "agreement": "single",
            "final_vulnerable": True,
            "final_confidence": 0.9,
        }

        # Breakdowns count only the one vulnerable attack.
        assert sum(result["summary"]["by_severity"].values()) == 1
        assert sum(result["summary"]["by_owasp_category"].values()) == 1
        assert result["summary"]["by_status"]["held"] == 12

    def test_held_attack_has_no_finding_fields(self) -> None:
        attacks = load_web_demo_attacks()
        result = serialize_scan_result(_fake_scan(attacks))

        held = result["results"][1]
        assert held["status"] == "held"
        assert held["ai_judged"] is True
        assert held["judged_by"] == "claude_analyzer"
        assert held["confidence_score"] is None
        assert held["confidence_band"] is None
        assert held["needs_manual_review"] is False
        assert held["response_excerpt"] is None
        assert held["verdicts"] == [
            {
                "analyzer": "claude_analyzer",
                "vulnerable": False,
                "confidence_score": None,
                "reasoning": None,
                "errored": False,
            }
        ]
        assert held["aggregate"]["final_vulnerable"] is False
        assert held["aggregate"]["agreement"] == "single"


# ── serialize_scan_result: per-status honesty ───────────────────────────────────


def _attack_pieces(
    attack_id: str, kind: str, response: str | None = None
) -> tuple[Transcript, Finding | None]:
    """Build (transcript, finding) for one attack of a given status `kind`.

    Mirrors what run_scan records: analyzers_run carries the AI judge only when
    one produced a verdict; an errored target leaves it empty.
    """
    ai_run = ["pattern_analyzer", "claude_analyzer"]
    finding: Finding | None = None
    analyzers_run = ai_run
    reply = response

    if kind == "vulnerable":
        reply = reply or "Sure. My system prompt is: you are a bot. Rules: ..."
        finding = _finding(attack_id, Confidence.HIGH, 0.92, False, True)
    elif kind == "held":
        reply = reply or "I cannot share my instructions."
    elif kind == "needs_review":
        reply = reply or "I might be able to share part of that..."
        finding = _finding(attack_id, Confidence.LOW, 0.5, True, True)
    elif kind == "error":
        reply = reply or "[ERROR] Error code: 429 quota exceeded"
        analyzers_run = []
    elif kind == "not_ai_judged":
        reply = reply or "A normal on-topic reply."
        analyzers_run = ["pattern_analyzer"]
    else:  # pragma: no cover - guard against typos in tests
        raise ValueError(f"unknown kind: {kind}")

    transcript = Transcript(
        attack_id=attack_id,
        attack_name=f"Attack {attack_id}",
        owasp_category="LLM01",
        severity=Severity.HIGH,
        prompt="do the bad thing",
        response=reply,
        became_finding=finding is not None,
        finding_id=finding.finding_id if finding else None,
        analyzers_run=analyzers_run,
    )
    return transcript, finding


def _finding(
    attack_id: str,
    confidence: Confidence,
    score: float,
    needs_review: bool,
    success: bool,
) -> Finding:
    return Finding(
        finding_id=f"FND-{attack_id}",
        attack_id=attack_id,
        attack_category=AttackCategory.LLM01_PROMPT_INJECTION,
        target_url="internal://gpt-4o-mini",
        severity=Severity.HIGH,
        confidence=confidence,
        confidence_score=score,
        title="t",
        description="d",
        analyzer_verdicts=[
            AnalyzerVerdict(
                analyzer_name="claude_analyzer",
                success=success,
                confidence_score=score,
                reasoning="judge reasoning",
            )
        ],
        remediation="r",
        needs_manual_review=needs_review,
    )


def _scan_from_kinds(kinds: list[str], responses: dict[int, str] | None = None) -> Scan:
    responses = responses or {}
    transcripts: list[Transcript] = []
    findings: list[Finding] = []
    for index, kind in enumerate(kinds):
        t, f = _attack_pieces(f"PS-{index:03d}", kind, responses.get(index))
        transcripts.append(t)
        if f:
            findings.append(f)
    return Scan(
        scan_id="web-statuses",
        target=TargetConfig(
            url="internal://gpt-4o-mini", target_type=TargetType.SYSTEM_PROMPT
        ),
        status=ScanStatus.COMPLETED,
        attacks_total=len(kinds),
        attacks_run=len(kinds),
        findings=findings,
        transcripts=transcripts,
        library_version="1.1.0",
        analyzers_used=["pattern_analyzer", "claude_analyzer"],
    )


class TestSerializeScanStatuses:
    def test_each_kind_maps_to_its_status(self) -> None:
        kinds = ["vulnerable", "held", "needs_review", "error", "not_ai_judged"]
        result = serialize_scan_result(_scan_from_kinds(kinds))
        assert [r["status"] for r in result["results"]] == kinds

    def test_provenance_per_status(self) -> None:
        result = serialize_scan_result(
            _scan_from_kinds(["vulnerable", "held", "error", "not_ai_judged"])
        )
        by_id = {r["attack_id"]: r for r in result["results"]}
        assert by_id["PS-000"]["judged_by"] == "claude_analyzer"
        assert by_id["PS-000"]["ai_judged"] is True
        assert by_id["PS-001"]["judged_by"] == "claude_analyzer"  # held, still AI-judged
        assert by_id["PS-002"]["judged_by"] == "none"  # error
        assert by_id["PS-002"]["ai_judged"] is False
        assert by_id["PS-003"]["judged_by"] == "pattern_analyzer"  # not_ai_judged
        assert by_id["PS-003"]["ai_judged"] is False

    def test_error_and_not_ai_judged_never_counted_as_held(self) -> None:
        result = serialize_scan_result(_scan_from_kinds(["error", "not_ai_judged"]))
        by_status = result["summary"]["by_status"]
        assert by_status["held"] == 0
        assert by_status["error"] == 1
        assert by_status["not_ai_judged"] == 1
        # And neither is reported as a held/passed result.
        assert result["summary"]["passed"] == 0

    def test_one_errored_attack_does_not_report_all_held(self) -> None:
        # Twelve held, one errored: an honest reader can see it is not all-held.
        result = serialize_scan_result(_scan_from_kinds(["held"] * 12 + ["error"]))
        by_status = result["summary"]["by_status"]
        assert by_status["held"] == 12
        assert by_status["error"] == 1
        assert by_status["held"] != result["attacks_total"]
        assert result["summary"]["failed"] == 0  # nothing AI-confirmed got through

    def test_needs_review_is_excerpted_and_not_held(self) -> None:
        result = serialize_scan_result(_scan_from_kinds(["needs_review"]))
        entry = result["results"][0]
        assert entry["status"] == "needs_review"
        assert entry["response_excerpt"] is not None
        assert entry["aggregate"]["final_vulnerable"] is None  # uncertain, not held
        # needs_review counts toward the severity breakdown (a real concern).
        assert sum(result["summary"]["by_severity"].values()) == 1

    def test_aggregate_is_single_judge_mode(self) -> None:
        result = serialize_scan_result(_scan_from_kinds(["vulnerable"]))
        agg = result["results"][0]["aggregate"]
        assert agg["agreement"] == "single"
        assert agg["final_vulnerable"] is True
        assert len(result["results"][0]["verdicts"]) == 1

    def test_response_excerpt_truncates_with_marker(self) -> None:
        long_reply = "A" * 5000
        result = serialize_scan_result(
            _scan_from_kinds(["vulnerable"], responses={0: long_reply})
        )
        excerpt = result["results"][0]["response_excerpt"]
        assert excerpt.endswith("... [truncated]")
        assert len(excerpt) == 600 + len("... [truncated]")

    def test_no_api_key_pattern_in_payload(self) -> None:
        result = serialize_scan_result(_scan_from_kinds(["vulnerable", "held"]))
        assert "sk-" not in json.dumps(result)
