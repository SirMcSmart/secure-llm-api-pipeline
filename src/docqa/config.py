"""Runtime settings, read from environment variables only (12-factor). No secrets have defaults."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_key_hashes() -> dict[str, str]:
    """API keys are stored only as SHA-256 hashes: {sha256_hex: user_id}.

    Source, in order: DOCQA_API_KEY_HASHES (JSON), or the file named by DOCQA_API_KEY_HASHES_FILE
    (e.g. a mounted secret). Keys are 256-bit random tokens, so an unsalted fast hash is adequate:
    there is nothing to brute-force, unlike a human password.
    """
    raw = os.environ.get("DOCQA_API_KEY_HASHES")
    path = os.environ.get("DOCQA_API_KEY_HASHES_FILE")
    if not raw and path:
        raw = Path(path).read_text(encoding="utf-8")
    if not raw:
        return {}
    data = json.loads(raw)
    return {str(k).lower(): str(v) for k, v in data.items()}


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("DOCQA_DATA_DIR", PROJECT_ROOT / "data")))
    db_path: str = field(default_factory=lambda: os.environ.get("DOCQA_DB_PATH", ":memory:"))
    api_key_hashes: dict[str, str] = field(default_factory=_load_key_hashes)
    llm_provider: str = field(default_factory=lambda: os.environ.get("DOCQA_LLM_PROVIDER", "mock"))
    llm_model: str = field(default_factory=lambda: os.environ.get("DOCQA_LLM_MODEL", "claude-opus-5-5"))
    max_question_chars: int = field(default_factory=lambda: int(os.environ.get("DOCQA_MAX_QUESTION_CHARS", "500")))
    max_output_tokens: int = field(default_factory=lambda: int(os.environ.get("DOCQA_MAX_OUTPUT_TOKENS", "1024")))
    top_k: int = field(default_factory=lambda: int(os.environ.get("DOCQA_TOP_K", "4")))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.environ.get("DOCQA_RATE_LIMIT_PER_MINUTE", "30")))
    # Defence-in-depth layers. They can be switched off only to prove that the
    # authorization boundary holds on its own (see tests/test_prompt_injection.py).
    input_guard: bool = field(default_factory=lambda: _bool("DOCQA_INPUT_GUARD", True))
    context_guard: bool = field(default_factory=lambda: _bool("DOCQA_CONTEXT_GUARD", True))
    output_guard: bool = field(default_factory=lambda: _bool("DOCQA_OUTPUT_GUARD", True))
    enable_docs: bool = field(default_factory=lambda: _bool("DOCQA_ENABLE_DOCS", False))
