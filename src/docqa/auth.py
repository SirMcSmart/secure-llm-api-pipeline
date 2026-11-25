"""Bearer API-key authentication. Keys are compared as SHA-256 hashes in constant time."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_key() -> str:
    return "dq_" + secrets.token_urlsafe(32)


def authenticate(authorization: str | None, key_hashes: dict[str, str]) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    presented = hash_key(authorization.removeprefix("Bearer ").strip())
    user = None
    for stored, owner in key_hashes.items():
        if hmac.compare_digest(stored, presented):  # no early exit: timing does not reveal a match
            user = owner
    return user
