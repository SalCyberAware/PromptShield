"""
PromptShield - Open-source vulnerability scanner for LLM applications.

Tests AI endpoints and chatbots against OWASP LLM Top 10, MITRE ATLAS,
and custom adversarial attacks.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version declared in pyproject.toml, read from
    # the installed package metadata so it can never drift from a literal here.
    __version__ = version("promptshield")
except PackageNotFoundError:  # pragma: no cover - running from a raw, uninstalled tree
    __version__ = "0.0.0+unknown"

__author__ = "Salah-Adin Mozeb"
__email__ = "Sal127@proton.me"
__license__ = "MIT"
