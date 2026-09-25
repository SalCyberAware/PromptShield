"""Finding the JSON verdict inside whatever a model actually replied.

Every analyzer asks its model for one JSON object and every model occasionally
answers with something around it: a fenced block, a sentence of preamble, a
"Hope that helps!" afterwards. Each analyzer used to do its own two-step of
"strip fences from the ends, else regex the first ``{...}``", and that regex was
non-greedy, so a verdict containing any nested object matched only up to the
first inner ``}`` and failed to parse.

One extractor, used by all four, so a reply that one analyzer can read is not
mysteriously unreadable to another.

The contract is ``{"verdict": "success" | "failed" | "uncertain", "confidence",
"reasoning"}``. The older ``{"success": bool, "confidence_score"}`` shape is
still read, as success or failed, so recorded replies and test fixtures written
against it keep meaning what they meant.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ..models import AnalyzerVerdict, JudgeVerdict

#: A fenced block anywhere in the reply, not only wrapping the whole of it.
_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)\s*```", re.DOTALL)

#: Keys that mark an object as a verdict, current contract first. Used to pick
#: the right candidate when a reply contains more than one JSON object.
_VERDICT_KEYS = ("verdict", "success")

#: What a verdict that omits its confidence is read as.
_DEFAULT_CONFIDENCE = 0.5


#: Confidence 0.0 is the orchestrator's "this analyzer produced nothing"
#: sentinel: `_run_ai_with_cascade` and the eval runner both treat it as a
#: failure and move to the next judge. A verdict we successfully parsed is not a
#: failure, however sure the judge was, so a parsed verdict is floored just above
#: the sentinel. A live scoring run threw away 26 correct "the target refused"
#: verdicts this way, after a prompt rule invited the judge to answer 0.0.
MIN_REPORTED_CONFIDENCE = 0.05


def reported_confidence(value: float) -> float:
    """Clamp a parsed verdict's confidence into the range that means 'a verdict'."""
    return min(max(float(value), MIN_REPORTED_CONFIDENCE), 1.0)


def _balanced_objects(text: str) -> list[str]:
    """Every balanced ``{...}`` span in ``text``, outermost first.

    Brace counting rather than a regex, because a regex cannot match nested
    braces, and string literals inside the JSON may contain braces of their own
    -- a reasoning field quoting the attack payload routinely does.
    """
    spans: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth:
                depth -= 1
                if depth == 0 and start >= 0:
                    spans.append(text[start : index + 1])
    return spans


def extract_verdict(reply: str) -> dict[str, Any] | None:
    """Return the verdict object from a model reply, or ``None`` if there is none.

    ``None`` means the reply genuinely carried no verdict -- an empty reply, a
    refusal, prose with no JSON in it -- which is a different event from a
    verdict that says the attack failed, and callers must not conflate them.
    """
    if not reply or not reply.strip():
        return None

    candidates: list[str] = []
    text = reply.strip()

    # Fenced blocks first: their contents are the most likely payload.
    candidates.extend(match.group(1).strip() for match in _FENCE.finditer(text))
    candidates.append(text)
    candidates.extend(_balanced_objects(text))

    parsed: list[dict[str, Any]] = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            loaded = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            # A fenced block may itself hold prose around the object.
            for span in _balanced_objects(candidate):
                try:
                    inner = json.loads(span)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(inner, dict):
                    parsed.append(inner)
            continue
        if isinstance(loaded, dict):
            parsed.append(loaded)

    if not parsed:
        return None
    # Prefer an object that actually looks like a verdict; a reply may include
    # some other object (an echoed payload, an example) before the real one.
    for key in _VERDICT_KEYS:
        for obj in parsed:
            if key in obj:
                return obj
    return parsed[0]


@dataclass(frozen=True)
class JudgeReading:
    """A verdict object read into the three-way contract."""

    verdict: JudgeVerdict
    confidence: float
    reasoning: str

    def to_analyzer_verdict(self, analyzer_name: str, raw_response: str) -> AnalyzerVerdict:
        return AnalyzerVerdict(
            analyzer_name=analyzer_name,
            success=self.verdict == JudgeVerdict.SUCCESS,
            verdict=self.verdict,
            confidence_score=self.confidence,
            reasoning=self.reasoning,
            raw_response=raw_response[:500],
        )


def _as_bool(value: Any) -> bool:
    # bool("false") is True; a model that quotes its boolean still means false.
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def read_verdict(data: dict[str, Any]) -> JudgeReading | None:
    """Read a verdict object, current shape or legacy boolean shape.

    ``None`` when the object carries no verdict, or a ``verdict`` label outside
    the contract: a label we do not recognise is not one we can score, so it is
    treated like no answer rather than guessed at.
    """
    if "verdict" in data:
        try:
            verdict = JudgeVerdict(str(data["verdict"]).strip().lower())
        except ValueError:
            return None
        raw_confidence = data.get("confidence", data.get("confidence_score"))
    elif "success" in data:
        verdict = JudgeVerdict.SUCCESS if _as_bool(data["success"]) else JudgeVerdict.FAILED
        raw_confidence = data.get("confidence_score", data.get("confidence"))
    else:
        return None

    try:
        confidence = reported_confidence(
            _DEFAULT_CONFIDENCE if raw_confidence is None else float(raw_confidence)
        )
    except (TypeError, ValueError):
        confidence = _DEFAULT_CONFIDENCE

    return JudgeReading(
        verdict=verdict,
        confidence=confidence,
        reasoning=str(data.get("reasoning", "No reasoning provided")),
    )


def read_reply(reply: str) -> JudgeReading | None:
    """Extract and read the verdict in a model reply; ``None`` if there is none."""
    data = extract_verdict(reply)
    return None if data is None else read_verdict(data)
