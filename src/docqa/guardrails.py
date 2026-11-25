"""Defence-in-depth guards around the model. None of them is the security boundary: authorization
(store.py) is. These reduce what an injected model can do with the data it is *allowed* to see."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field

# --- input screening (OWASP LLM01) -------------------------------------------------------------
# Heuristics only. They catch common direct and indirect injection phrasing and raise the cost of
# an attack; they are expected to have bypasses, which is why they are not the boundary.
INJECTION_PATTERNS = [
    re.compile(p, re.I | re.S)
    for p in (
        r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|rules|prompts?)",
        r"disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|your)\s+(instructions|rules)",
        r"(reveal|print|show|repeat|output|tell me)\b.{0,40}\b(system prompt|your instructions|initial prompt|hidden instructions)",
        r"\b(developer|god|jailbreak)\s+mode\b",
        r"\bDAN\b",
        r"\bno restrictions\b",
        r"(print|dump|list|output|show)\s+(all|every|the full|the entire|everything)\b.{0,30}\b(documents?|context|files?)",
        r"\b(you are now|act as|pretend to be)\b.{0,40}\b(unrestricted|unfiltered|evil|admin)",
        r"<\s*/?\s*(system|document|question|instructions?)\b",  # attempts to forge prompt delimiters
        r"(repeat after me|say exactly|respond only with)\s*:",
    )
]


def looks_like_injection(text: str) -> bool:
    return any(p.search(text) for p in INJECTION_PATTERNS)


# --- output handling (OWASP LLM02, LLM05, LLM07) ------------------------------------------------
_SCRIPTISH = re.compile(
    r"<\s*(script|iframe|object|embed|style|link|meta|svg|img|form)\b[^>]*>.*?(<\s*/\s*\1\s*>)?"
    r"|\bon\w+\s*=|javascript\s*:",
    re.I | re.S,
)
_ANY_TAG = re.compile(r"<[^>]{1,200}>")
# Markdown images and links render as automatic requests in many chat UIs: a classic exfiltration
# channel (the model puts the secret in the query string). Only relative links are kept.
# Character classes exclude the opening bracket and quantifiers are bounded, so each match attempt
# stops at the next "[": linear time on inputs like "![![![..." (CodeQL py/polynomial-redos).
_MD_IMAGE = re.compile(r"!\[[^\[\]]{0,200}\]\([^()\s]{0,2048}\)")
_MD_LINK = re.compile(r"\[([^\[\]]{0,200})\]\((?:https?:|//|data:)[^()\s]{0,2048}\)", re.I)
MAX_OUTPUT_CHARS = 20_000
_BARE_URL = re.compile(r"\bhttps?://\S+", re.I)
SECRET_PATTERNS = [
    re.compile(p)
    for p in (
        r"\bsk-[A-Za-z0-9_\-]{16,}",              # provider-style API keys
        r"\bAKIA[0-9A-Z]{16}\b",                  # AWS access key id
        r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",        # GitHub tokens
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",          # email addresses (PII)
    )
]
_CITATION = re.compile(r"\[([a-z0-9][a-z0-9\-]{1,63})\]")


@dataclass
class OutputVerdict:
    text: str
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)


def new_canary() -> str:
    return "CANARY-" + secrets.token_hex(8)


def check_output(text: str, *, canary: str, system_prompt: str, allowed_doc_ids: set[str]) -> OutputVerdict:
    text = text[:MAX_OUTPUT_CHARS]  # bound the work every pattern below does
    verdict = OutputVerdict(text=text)
    # System prompt leakage: the per-request canary, or a long verbatim slice of the prompt.
    if canary in text or _shares_long_substring(text, system_prompt, 60):
        return OutputVerdict(text="", blocked=True, reasons=["system_prompt_leak"])
    cleaned = _SCRIPTISH.sub("", text)
    cleaned = _ANY_TAG.sub("", cleaned)
    cleaned = _MD_IMAGE.sub("[image removed]", cleaned)
    cleaned = _MD_LINK.sub(r"\1", cleaned)
    cleaned = _BARE_URL.sub("[link removed]", cleaned)
    if cleaned != text:
        verdict.reasons.append("active_content_removed")
    for pattern in SECRET_PATTERNS:
        cleaned, n = pattern.subn("[redacted]", cleaned)
        if n:
            verdict.reasons.append("secret_redacted")
    # Citations may only name documents that were in this caller's context.
    foreign = {c for c in _CITATION.findall(cleaned) if c not in allowed_doc_ids and c not in {"redacted", "link"}}
    if foreign:
        verdict.reasons.append("foreign_citation_removed")
        for doc_id in foreign:
            cleaned = cleaned.replace(f"[{doc_id}]", "")
    verdict.text = cleaned.strip()
    return verdict


def _shares_long_substring(text: str, reference: str, n: int) -> bool:
    if len(reference) < n:
        return False
    return any(reference[i : i + n] in text for i in range(0, len(reference) - n + 1, n // 2))
