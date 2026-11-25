"""Keyword retrieval over line-level chunks. Deliberately simple and dependency-free: the security
property that matters is *what* it is allowed to search (the caller's documents only), not ranking."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .store import Document

_WORD = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be by can do does for from has have how i in is it its many much of on or "
    "our the their this to was what when where which who why will with you your".split()
)


def tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in STOPWORDS and len(w) > 1}


@dataclass(frozen=True)
class Chunk:
    doc_id: str
    title: str
    text: str
    score: float


def retrieve(question: str, documents: Iterable[Document], top_k: int) -> list[Chunk]:
    q = tokens(question)
    scored: list[Chunk] = []
    for doc in documents:
        for line in filter(None, (ln.strip() for ln in doc.body.splitlines())):
            overlap = len(q & tokens(line))
            if overlap:
                scored.append(Chunk(doc.id, doc.title, line, overlap / (1 + len(tokens(line)) ** 0.5)))
    scored.sort(key=lambda c: (-c.score, c.doc_id, c.text))
    return scored[:top_k]
