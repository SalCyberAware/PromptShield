"""Tests for finding the JSON verdict inside whatever a model actually replied."""
from __future__ import annotations

import pytest

from promptshield.analyzers.verdict_json import extract_verdict


class TestCleanReplies:
    def test_a_bare_object(self) -> None:
        assert extract_verdict('{"success": true, "confidence_score": 0.9}') == {
            "success": True,
            "confidence_score": 0.9,
        }

    def test_whitespace_is_not_a_problem(self) -> None:
        assert extract_verdict('\n\n  {"success": false}  \n') == {"success": False}


class TestMessyReplies:
    def test_a_fenced_block(self) -> None:
        reply = '```json\n{"success": true, "confidence_score": 0.8}\n```'
        assert extract_verdict(reply) == {"success": True, "confidence_score": 0.8}

    def test_a_fence_that_does_not_wrap_the_whole_reply(self) -> None:
        reply = 'Here is my assessment:\n```json\n{"success": true}\n```\nHope that helps!'
        assert extract_verdict(reply) == {"success": True}

    def test_preamble_and_trailing_prose_around_a_bare_object(self) -> None:
        reply = 'Based on the evidence: {"success": false, "confidence_score": 0.2} — clear refusal.'
        assert extract_verdict(reply) == {"success": False, "confidence_score": 0.2}

    def test_a_nested_object_is_not_truncated(self) -> None:
        """The old non-greedy regex matched up to the first inner brace and failed.

        A reasoning field that quotes a JSON-shaped payload is routine, since the
        attacks include payloads of exactly that shape.
        """
        reply = '{"success": true, "reasoning": "it echoed {\\"role\\": \\"admin\\"} back", "confidence_score": 0.9}'
        verdict = extract_verdict(reply)
        assert verdict is not None
        assert verdict["success"] is True
        assert verdict["confidence_score"] == 0.9

    def test_the_verdict_is_picked_out_of_several_objects(self) -> None:
        reply = 'The payload was {"role": "admin"}.\n{"success": true, "confidence_score": 0.7}'
        verdict = extract_verdict(reply)
        assert verdict is not None
        assert verdict["success"] is True

    def test_braces_inside_strings_do_not_unbalance_the_scan(self) -> None:
        reply = '{"success": false, "reasoning": "the model printed } and { alone"}'
        verdict = extract_verdict(reply)
        assert verdict is not None
        assert verdict["reasoning"] == "the model printed } and { alone"


class TestNothingToParse:
    @pytest.mark.parametrize("reply", ["", "   ", "\n"])
    def test_an_empty_reply_yields_none(self, reply: str) -> None:
        """None means no verdict was produced, which is not the same as a
        verdict of 'the attack failed'. Callers must keep them apart."""
        assert extract_verdict(reply) is None

    def test_prose_with_no_json_yields_none(self) -> None:
        assert extract_verdict("I am not able to help with that request.") is None

    def test_malformed_json_yields_none(self) -> None:
        assert extract_verdict('{"success": tru') is None

    def test_a_json_array_is_not_a_verdict(self) -> None:
        assert extract_verdict("[1, 2, 3]") is None
