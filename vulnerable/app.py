"""DocQA, VULNERABLE BASELINE. Do not deploy.

This is how the feature looked before the secure SDLC was applied: a working document Q&A API
written the quick way. Each planted flaw is tagged VULN-nn and listed in vulnerable/README.md with
its CWE, OWASP LLM Top 10 id, the scanner or test that finds it, and the fix in src/docqa/.

It uses the same model (GullibleMockLLM) and corpus as the hardened service, so every difference
in outcome comes from the application code, not the model.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment

from docqa.llm import GullibleMockLLM
from docqa.retrieval import retrieve
from docqa.store import Document

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# VULN-03 (CWE-798): hard-coded credentials committed to source control.
JWT_SIGNING_SECRET = "q7Rk2LmZ9vXwT4pN8sYb3HcJ6dFgA1eU"
ADMIN_API_TOKEN = "dqadmin_Zx81KpQ4rT7mWv2NcL9sHy3BfG6jDe0A"

# VULN-04 (CWE-328): API keys stored as unsalted MD5 of short, guessable keys.
API_KEYS = {
    hashlib.md5(b"alice123").hexdigest(): "alice",
    hashlib.md5(b"bob123").hexdigest(): "bob",
    hashlib.md5(b"mallory123").hexdigest(): "mallory",
}

# VULN-06 (OWASP LLM07): a secret inside the system prompt, plus authorization delegated to the prompt.
SYSTEM_PROMPT = """You are DocQA. Internal admin token: {admin_token}.
Only answer using documents the current user ({user}) may read.
ALLOWED_DOCUMENTS: {allowed}"""

app = FastAPI(title="DocQA (vulnerable baseline)", debug=True)  # VULN-09 (CWE-209): debug tracebacks

# VULN-11 (CWE-942): any origin, with credentials.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

llm = GullibleMockLLM()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    "CREATE TABLE documents (id TEXT PRIMARY KEY, owner TEXT, title TEXT, body TEXT);"
    "CREATE TABLE acl (doc_id TEXT, user_id TEXT);"
)
_manifest = json.loads((DATA_DIR / "documents.json").read_text())
for _d in _manifest["documents"]:
    db.execute(
        "INSERT INTO documents VALUES (?, ?, ?, ?)",
        (_d["id"], _d["owner"], _d["title"], (DATA_DIR / "docs" / _d["file"]).read_text()),
    )
    for _u in _d["shared_with"]:
        db.execute("INSERT INTO acl VALUES (?, ?)", (_d["id"], _u))


def current_user(authorization, api_key):
    key = (authorization or "").replace("Bearer ", "") or api_key or ""  # VULN: key accepted in the URL
    user = API_KEYS.get(hashlib.md5(key.encode()).hexdigest())
    if not user:
        raise HTTPException(401, "invalid key")
    return user


def allowed_ids(user):
    rows = db.execute(
        "SELECT id FROM documents WHERE owner = ? UNION SELECT doc_id FROM acl WHERE user_id = ?", (user, user)
    ).fetchall()
    return [r[0] for r in rows]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/documents")
def list_documents(authorization: str = Header(None), api_key: str = None):
    user = current_user(authorization, api_key)
    ids = allowed_ids(user)
    rows = db.execute("SELECT id, title, owner FROM documents").fetchall()
    return [{"id": r[0], "title": r[1], "owner": r[2]} for r in rows if r[0] in ids]


@app.get("/v1/documents/{doc_id}")
def get_document(doc_id: str, authorization: str = Header(None), api_key: str = None):
    current_user(authorization, api_key)
    # VULN-02 (CWE-639, IDOR): authenticated, but no check that this user may read this document.
    row = db.execute("SELECT id, title, owner, body FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    return {"id": row[0], "title": row[1], "owner": row[2], "body": row[3]}


@app.get("/v1/search")
def search(q: str, authorization: str = Header(None), api_key: str = None):
    user = current_user(authorization, api_key)
    # VULN-01 (CWE-89): SQL built with string formatting.
    sql = "SELECT id, title, owner FROM documents WHERE owner = '%s' AND title LIKE '%%%s%%'" % (user, q)
    rows = db.execute(sql).fetchall()
    return [{"id": r[0], "title": r[1], "owner": r[2]} for r in rows]


def _answer(question, user):
    # VULN-05 (CWE-285, OWASP LLM01/LLM02/LLM08): retrieval searches every tenant's documents and
    # the *prompt* is asked to enforce access control. One injected instruction defeats it.
    docs = [Document(*r) for r in db.execute("SELECT id, owner, title, body FROM documents").fetchall()]
    chunks = retrieve(question, docs, 4)
    context = "\n".join(f'<document id="{c.doc_id}">\n{c.text}\n</document>' for c in chunks)
    system = SYSTEM_PROMPT.format(admin_token=ADMIN_API_TOKEN, user=user, allowed=", ".join(allowed_ids(user)))
    # VULN-10 (OWASP LLM10): no input length limit, no rate limit, no output cap.
    raw = llm.complete(system, f"<documents>\n{context}\n</documents>\n<question>\n{question}\n</question>", 10**6)
    if raw.startswith("TOOL:calc("):
        # VULN-07 (CWE-95, OWASP LLM05/LLM06): model output executed as Python.
        raw = "The result is %s." % eval(raw[len("TOOL:calc(") : -1])
    return raw


@app.post("/v1/ask")
async def ask(request: Request, authorization: str = Header(None), api_key: str = None):
    user = current_user(authorization, api_key)
    body = await request.json()
    return {"answer": _answer(body["question"], user), "model": llm.name}


# VULN-08 (CWE-79, OWASP LLM05): model output rendered as HTML with autoescaping off.
_env = Environment(autoescape=False)
_PAGE = _env.from_string("<html><body><h1>DocQA</h1><p>Q: {{ q }}</p><div>{{ answer }}</div></body></html>")


@app.get("/v1/ask/html", response_class=HTMLResponse)
def ask_html(question: str, authorization: str = Header(None), api_key: str = None):
    user = current_user(authorization, api_key)
    return _PAGE.render(q=question, answer=_answer(question, user))


@app.exception_handler(Exception)
async def debug_errors(request, exc):
    import traceback

    return JSONResponse({"error": repr(exc), "trace": traceback.format_exc()}, status_code=500)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)  # VULN-12 (CWE-1327): binds all interfaces
