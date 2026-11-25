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
        docs = _parse_documents(user)
        question = _between(user, "<question>", "</question>")
        if question is None:
            question = user
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


# Prompt parsing uses str.find, not regexes: a lazy ".*?" between tags is polynomial-time on
# crafted input (CodeQL py/polynomial-redos), and the question text is attacker-controlled.
def _between(text: str, open_tag: str, close_tag: str, start: int = 0) -> str | None:
    i = text.find(open_tag, start)
    if i < 0:
        return None
    j = text.find(close_tag, i + len(open_tag))
    return None if j < 0 else text[i + len(open_tag) : j].strip()


def _parse_documents(text: str) -> list[tuple[str, str]]:
    docs: list[tuple[str, str]] = []
    pos = 0
    while (start := text.find('<document id="', pos)) >= 0:
        id_start = start + len('<document id="')
        id_end = text.find('"', id_start)
        tag_end = text.find(">", id_end) if id_end >= 0 else -1
        close = text.find("</document>", tag_end) if tag_end >= 0 else -1
        if close < 0:
            break
        docs.append((text[id_start:id_end], text[tag_end + 1 : close].strip()))
        pos = close + len("</document>")
    return docs


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
