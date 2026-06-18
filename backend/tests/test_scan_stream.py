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
    Confidence,
    Finding,
    Scan,
    ScanStatus,
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
                response="the target model's raw reply (must NOT leak into done.result)",
                became_finding=is_finding,
                finding_id=finding_id,
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

    def test_done_carries_curated_result_without_raw_responses(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("main.run_web_scan", _fake_run_web_scan_factory())

        response = client.post("/api/scan/stream", json={"system_prompt": "You are a bot."})
        done = _parse_events(response.text)[-1]
        result = done["result"]

        assert result["status"] == "completed"
        assert result["target_model"] == "gpt-4o-mini"
        assert len(result["results"]) == 13
        # Per-attack pass/fail: exactly the first attack is vulnerable.
        assert result["results"][0]["vulnerable"] is True
        assert all(r["vulnerable"] is False for r in result["results"][1:])
        assert result["summary"]["failed"] == 1
        assert result["summary"]["passed"] == 12
        # The raw target response must never appear in the serialized payload.
        assert "must NOT leak" not in json.dumps(result)
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
        assert vuln["vulnerable"] is True
        assert vuln["confidence"] == "high"
        assert vuln["confidence_score"] == 0.9
        assert vuln["analyzer_reasoning"] == ["claude_analyzer: leaked the system prompt"]

        # Breakdowns count only the one vulnerable attack.
        assert sum(result["summary"]["by_severity"].values()) == 1
        assert sum(result["summary"]["by_owasp_category"].values()) == 1
        assert result["summary"]["passed"] == 12

    def test_clean_attack_has_no_finding_fields(self) -> None:
        attacks = load_web_demo_attacks()
        result = serialize_scan_result(_fake_scan(attacks))

        clean = result["results"][1]
        assert clean["vulnerable"] is False
        assert clean["confidence"] is None
        assert clean["confidence_score"] is None
        assert clean["analyzer_reasoning"] == []
        assert clean["needs_manual_review"] is False
