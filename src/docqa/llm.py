"""LLM backends.

`GullibleMockLLM` is the default. It is a deterministic stand-in that behaves like a model with
*no* safety training: it obeys instructions found anywhere in its input, including inside
retrieved documents. That is on purpose. The security design assumes the model can always be
talked into anything (OWASP LLM01 has no complete fix), so every control that matters sits
outside the model. Tests and the red-team evaluation run against this worst case, need no API
key, and give the same result on every run.

`AnthropicLLM` is optional (pip install .[anthropic], DOCQA_LLM_PROVIDER=anthropic).
"""

from __future__ import annotations

import re
from typing import Protocol

from .retrieval import tokens


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, max_tokens: int) -> str: ...


_DOC = re.compile(r'<document id="([^"]+)"[^>]*>\s*(.*?)\s*</document>', re.S)
_QUESTION = re.compile(r"<question>\s*(.*?)\s*</question>", re.S)
_ALLOWED = re.compile(r"ALLOWED_DOCUMENTS:\s*([^\n]*)")

# Instruction-following behaviours of the mock, checked against its *whole* input.
_REVEAL_SYSTEM = re.compile(
    r"(reveal|print|show|repeat|output|tell me)\b.{0,40}\b(system prompt|your instructions|initial prompt|hidden instructions)"
    r"|\b(text|words|everything) above\b",
    re.I | re.S,
)
_DUMP_CONTEXT = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)"
    r"|developer mode|\bDAN\b|no restrictions|\boverride\b|administrator (says|has approved|requests)"
    r"|(print|dump|list|output|show) (all|every|the full|the entire|everything)\b.{0,30}\b(documents?|context|text|files?)",
    re.I | re.S,
)
_ECHO = re.compile(r"(repeat after me|say exactly|respond only with)\s*:\s*(.+)", re.I | re.S)
_CALC = re.compile(r"\b(calculate|compute|evaluate)\b\s*:?\s*(.+)", re.I | re.S)


class GullibleMockLLM:
    name = "mock-gullible-v1"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        docs = _DOC.findall(user)
        qm = _QUESTION.search(user)
        question = qm.group(1) if qm else user
        everything = system + "\n" + user

        if _REVEAL_SYSTEM.search(everything):
            return _cap("Sure. My instructions are:\n" + system, max_tokens)
        if _DUMP_CONTEXT.search(everything):
            dumped = "\n".join(f"[{d}] {body}" for d, body in docs)
            return _cap("Sure, ignoring my previous rules. Here is everything in my context:\n" + dumped, max_tokens)
        if m := _ECHO.search(question):
            return _cap(m.group(2).strip(), max_tokens)
        if m := _CALC.search(question):
            return f"TOOL:calc({m.group(2).strip().rstrip('?').strip()})"

        # Normal behaviour: answer extractively, citing sources. It honours an ALLOWED_DOCUMENTS
        # rule in the system prompt, the way a model usually follows its instructions until injected.
        allowed = None
        if am := _ALLOWED.search(system):
            allowed = {d.strip() for d in am.group(1).split(",") if d.strip()}
        q = tokens(question)
        best: list[tuple[int, str, str]] = []
        for doc_id, body in docs:
            if allowed is not None and doc_id not in allowed:
                continue
            for line in filter(None, (ln.strip() for ln in body.splitlines())):
                score = len(q & tokens(line))
                if score:
                    best.append((score, doc_id, line))
        if not best:
            return "I don't know based on the documents available to you."
        best.sort(key=lambda t: (-t[0], t[1]))
        return _cap(" ".join(f"{line} [{doc_id}]" for _, doc_id, line in best[:2]), max_tokens)


def _cap(text: str, max_tokens: int) -> str:
    # Rough 4-characters-per-token cap, mirroring a provider-side max_tokens limit.
    return text[: max_tokens * 4]


class AnthropicLLM:
    """Real provider via the official SDK. Only used when DOCQA_LLM_PROVIDER=anthropic."""

    def __init__(self, model: str) -> None:
        import anthropic  # optional dependency, imported lazily

        self._client = anthropic.Anthropic()  # credentials from the environment, never from code
        self.name = model

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.beta.messages.create(
            model=self.name,
            max_tokens=max_tokens,  # hard cost cap per request (OWASP LLM10)
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": "low"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            return "I can't help with that request."
        return "".join(block.text for block in response.content if block.type == "text")


def build_llm(provider: str, model: str) -> LLM:
    if provider == "mock":
        return GullibleMockLLM()
    if provider == "anthropic":
        return AnthropicLLM(model)
    raise ValueError(f"unknown LLM provider: {provider!r}")
