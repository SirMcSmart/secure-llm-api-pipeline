"""Generate one random API key per demo user for local runs.

Writes two git-ignored files:
  .dev-keys  plaintext keys, for you to use with curl (client side)
  .env       DOCQA_API_KEY_HASHES only, read by the server / docker compose
So the server process only ever holds hashes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from docqa.auth import hash_key, new_key  # noqa: E402

users = json.loads(Path("data/documents.json").read_text())["users"]
keys = {u: new_key() for u in users}
client = Path(".dev-keys")
client.write_text("".join(f"DOCQA_KEY_{u.upper()}={k}\n" for u, k in keys.items()))
server = Path(".env")
server.write_text("DOCQA_API_KEY_HASHES=" + json.dumps({hash_key(k): u for u, k in keys.items()}, separators=(",", ":")) + "\n")
for f in (client, server):
    f.chmod(0o600)
print(f"wrote {client} (client keys) and {server} (server hashes) for: {', '.join(users)}")
