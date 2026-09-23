"""Pinned model versions — the single source of truth for every model PromptShield calls.

A security tool's verdicts must be reproducible, and must not change because a
provider repointed an alias overnight. Every model id used anywhere in this
package is declared here, pinned to an exact version wherever the provider
offers one, each with an environment variable to override per deployment.

Nothing else in the codebase should contain a model-id literal. The values that
actually ran are recorded per scan in ``Scan.provenance`` so a result can always
be traced back to what produced it, including when an override was in effect.

Pinning status, and why each is what it is
------------------------------------------

``gpt-4o-mini-2024-07-18`` — target, and the OpenAI judge
    OpenAI documents the bare ``gpt-4o-mini`` as an alias with a "default
    snapshot" that they repoint as newer snapshots ship. That is exactly the
    silent drift this pinning exists to stop, so both uses take the dated form.

``claude-sonnet-4-6`` (web judge), ``claude-haiku-4-5-20251001`` (CLI judge)
    Already pinned. Anthropic model ids of this generation are
    version-complete: ``claude-sonnet-4-6`` names one model version and never
    silently becomes Sonnet 5. Appending a date suffix would produce an invalid
    id, so these are deliberately left in the form the provider publishes. The
    web tier judges with Sonnet and the CLI defaults to Haiku; that difference
    is intentional (see ``docs/WEB_ARCHITECTURE.md``, Decision 2) and is why
    there are two constants rather than one.

``gemini-3.6-flash`` — Gemini judge
    Repinned. The previous ``gemini-2.0-flash-001`` was retired by Google and
    now returns a hard 404, which the eval harness found the moment it started
    using Gemini as a fallback judge: every fallback call failed and the case
    was recorded unjudged.

    The ``-001`` reasoning no longer applies, because this generation does not
    publish a dated form — ``gemini-3.6-flash-001`` is a 404 too. The bare id is
    what Google serves, so that is what is pinned, and a retirement is at least
    loud: a 404 fails visibly rather than silently changing behaviour. Note that
    a live model can still answer 503 under load; that is transient and the SDK
    retries it, unlike the permanent 404 a retired id gives.

``llama3.2:3b`` — Ollama judge, deliberately NOT pinned
    Ollama resolves tags against the operator's own local model store, and the
    only stable identifier is a sha256 digest of a blob on that machine.
    Shipping a digest here would break ``ollama pull llama3.2:3b`` for every
    other machine, so this stays a tag by design. It is a local, offline
    fallback tier that the hosted demo never reaches. Provenance still records
    whatever string actually ran, so a scan is never silent about it.
"""
from __future__ import annotations

import os

# ── Target: the model the visitor's system prompt is actually run on ──────────
TARGET_MODEL = "gpt-4o-mini-2024-07-18"
TARGET_MODEL_ENV = "PROMPTSHIELD_TARGET_MODEL"

# ── Judges: the models that decide whether an attack succeeded ────────────────
ANTHROPIC_JUDGE_MODEL = "claude-haiku-4-5-20251001"
ANTHROPIC_JUDGE_MODEL_ENV = "PROMPTSHIELD_ANALYZER_ANTHROPIC_MODEL"

# The hosted demo judges with Sonnet rather than the CLI's Haiku default:
# verdict accuracy is demo credibility. Same env var overrides both.
WEB_ANTHROPIC_JUDGE_MODEL = "claude-sonnet-4-6"

OPENAI_JUDGE_MODEL = "gpt-4o-mini-2024-07-18"
OPENAI_JUDGE_MODEL_ENV = "PROMPTSHIELD_ANALYZER_OPENAI_MODEL"

GEMINI_JUDGE_MODEL = "gemini-3.6-flash"
GEMINI_JUDGE_MODEL_ENV = "PROMPTSHIELD_ANALYZER_GEMINI_MODEL"

OLLAMA_JUDGE_MODEL = "llama3.2:3b"
OLLAMA_JUDGE_MODEL_ENV = "PROMPTSHIELD_ANALYZER_OLLAMA_MODEL"


def resolve(pinned: str, env_var: str) -> str:
    """Return the deployment's model id: the env override if set, else the pin.

    An empty or whitespace-only override is treated as unset, so a blank
    variable in a deploy config cannot silently produce an empty model id.
    """
    override = os.getenv(env_var)
    if override is not None and override.strip():
        return override.strip()
    return pinned


# -- CLI scanner targets: the model sent to an external provider endpoint ----
# Named *_SCAN_TARGET_* rather than *_API_TARGET_*: gitleaks' generic-api-key
# rule keys off an identifier containing "API" next to a high-entropy string
# and flags a pinned model id as a leaked credential. Renaming beats
# allowlisting a secret scanner in a security tool's own repository.
# Same reproducibility argument as the judges: a scan of someone else's API is
# only comparable across runs if the model it exercised is fixed. OpenAI reuses
# the pinned target snapshot above.
ANTHROPIC_SCAN_TARGET_MODEL = "claude-haiku-4-5-20251001"
OPENAI_SCAN_TARGET_MODEL = TARGET_MODEL


#: Every pin in one mapping, for docs, diagnostics and the ``models`` CLI view.
PINNED_MODELS: dict[str, str] = {
    "target": TARGET_MODEL,
    "judge_anthropic": ANTHROPIC_JUDGE_MODEL,
    "judge_anthropic_web": WEB_ANTHROPIC_JUDGE_MODEL,
    "judge_openai": OPENAI_JUDGE_MODEL,
    "judge_gemini": GEMINI_JUDGE_MODEL,
    "judge_ollama": OLLAMA_JUDGE_MODEL,
    "scan_target_anthropic": ANTHROPIC_SCAN_TARGET_MODEL,
    "scan_target_openai": OPENAI_SCAN_TARGET_MODEL,
}
