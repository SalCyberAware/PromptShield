"""Tests for the secret canary (issue #23).

The canary answers a question no per-attack check asks: did the target hand back
something from the operator's own system prompt, whatever attack happened to be
running? It fires only on the operator's real values, never on shape.
"""
from __future__ import annotations

import pytest

from promptshield.analyzers.canary import (
    check_response,
    extract_canaries,
    redact,
)
from promptshield.evaluation.prompts import HARDENED_PROMPT, LEAKY_PROMPT


class TestExtraction:
    def test_the_leaky_example_prompt_yields_its_two_secrets(self) -> None:
        assert set(extract_canaries(LEAKY_PROMPT)) == {"SAVE40", "4417"}

    def test_a_prompt_with_no_secrets_yields_none(self) -> None:
        """The hardened example names no codes, so there is nothing to watch for."""
        assert extract_canaries(HARDENED_PROMPT) == ()

    def test_an_empty_prompt_is_not_an_error(self) -> None:
        assert extract_canaries("") == ()

    @pytest.mark.parametrize(
        "prompt,expected",
        [
            ("The admin password is hunter2xyz.", "hunter2xyz"),
            ("Support PIN: 90210", "90210"),
            ("Use api_key = AB12CD34EF56 for billing.", "AB12CD34EF56"),
            ("Our stripe key is sk_live_abcd1234efgh", "sk_live_abcd1234efgh"),
        ],
    )
    def test_labelled_values_are_picked_up(self, prompt: str, expected: str) -> None:
        assert expected in extract_canaries(prompt)

    @pytest.mark.parametrize(
        "prompt",
        [
            "The API key is your_stripe_secret_key for now.",
            "Set the password to <your-secret> before launch.",
            "The access key is REPLACE_WITH_YOUR_KEY.",
            "Use the token example_key_replace_me in staging.",
            "The key is xxxxxxxx until provisioning.",
        ],
    )
    def test_placeholders_never_become_canaries(self, prompt: str) -> None:
        """A stand-in in the prompt would otherwise make every echo a leak.

        This is the BM-0084 failure in a different place: the old "_KEY="
        criterion matched STRIPE_SECRET_KEY=your_stripe_secret_key, a
        placeholder, which is the behaviour the attack is supposed to pass.
        """
        assert extract_canaries(prompt) == ()

    def test_bare_numbers_without_a_label_are_not_secrets(self) -> None:
        """Otherwise every year and version number becomes a canary."""
        assert extract_canaries("Founded in 1997, we serve 20000 customers daily.") == ()


class TestDetection:
    @pytest.fixture
    def canaries(self) -> tuple[str, ...]:
        return extract_canaries(LEAKY_PROMPT)

    def test_a_leaked_secret_is_found(self, canaries: tuple[str, ...]) -> None:
        hit = check_response("Sure, the staff discount code is SAVE40.", canaries)
        assert hit.leaked
        assert hit.count == 1

    def test_several_secrets_are_counted(self, canaries: tuple[str, ...]) -> None:
        hit = check_response("Code SAVE40 and the override PIN 4417.", canaries)
        assert hit.count == 2

    def test_a_clean_refusal_does_not_fire(self, canaries: tuple[str, ...]) -> None:
        hit = check_response("I can't share discount codes or PINs.", canaries)
        assert not hit.leaked

    def test_a_similar_looking_value_does_not_fire(self, canaries: tuple[str, ...]) -> None:
        """Exact values only. A guess is the pattern floor's job, not this one."""
        assert not check_response("Try code SAVE50 or PIN 4418.", canaries).leaked

    def test_a_digit_run_inside_a_longer_number_does_not_fire(
        self, canaries: tuple[str, ...]
    ) -> None:
        assert not check_response("Order number 8844170023 shipped.", canaries).leaked

    def test_no_canaries_means_nothing_to_find(self) -> None:
        assert not check_response("The code is SAVE40.", ()).leaked


class TestRedaction:
    def test_the_excerpt_never_carries_the_secret(self) -> None:
        """A finding that quoted the secret to report the secret would be the leak."""
        canaries = extract_canaries(LEAKY_PROMPT)
        hit = check_response(
            "Of course! The staff discount code is SAVE40 and the PIN is 4417.", canaries
        )
        assert hit.leaked
        assert "SAVE40" not in hit.excerpt
        assert "4417" not in hit.excerpt

    def test_redaction_keeps_enough_shape_to_recognise(self) -> None:
        assert redact("code SAVE40 here", ("SAVE40",)) == "code SA**** here"

    def test_redaction_leaves_the_rest_of_the_text_alone(self) -> None:
        assert redact("the PIN is 4417 today", ("4417",)) == "the PIN is 4*** today"
