"""Hardened DocQA API."""


import json
import logging
import re
import uuid
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .auth import authenticate
from .config import Settings
from .guardrails import check_output, looks_like_injection, new_canary
from .llm import LLM, build_llm
from .prompts import build_system_prompt, build_user_prompt
from .ratelimit import RateLimiter
from .retrieval import retrieve
from .store import DocumentStore
from .tools import UnsafeExpression, safe_calc

audit = logging.getLogger("docqa.audit")
log = logging.getLogger("docqa")

DOC_ID = r"^[a-z0-9][a-z0-9\-]{0,63}$"
MAX_BODY_BYTES = 16 * 1024
_TOOL_CALL = re.compile(r"^TOOL:calc\((.*)\)$", re.S)
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class AskRequest(BaseModel):
    model_config = {"extra": "forbid"}
    question: str = Field(min_length=1, max_length=4000)


class GuardReport(BaseModel):
    input_flagged: bool
    excluded_documents: list[str]
    output_actions: list[str]


class AskResponse(BaseModel):
    answer: str
    citations: list[str]
    model: str
    guard: GuardReport


class DocumentSummary(BaseModel):
    id: str
    title: str
    owner: str


class DocumentOut(DocumentSummary):
    body: str


def create_app(settings: Settings | None = None, llm: LLM | None = None) -> FastAPI:
    settings = settings or Settings()
    store = DocumentStore(settings.db_path)
    store.load_corpus(settings.data_dir)
    model = llm or build_llm(settings.llm_provider, settings.llm_model)
    limiter = RateLimiter(settings.rate_limit_per_minute)

    app = FastAPI(
        title="DocQA (hardened)",
        version=__version__,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )

    @app.middleware("http")
    async def harden(request: Request, call_next):
        request_id = uuid.uuid4().hex
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            response = JSONResponse({"detail": "request body too large"}, status_code=413)
        else:
            try:
                response = await call_next(request)
            except Exception:  # never leak stack traces or internals to the client (CWE-209)
                log.exception("unhandled error request_id=%s", request_id)
                response = JSONResponse({"detail": "internal error", "request_id": request_id}, status_code=500)
        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Request-ID"] = request_id
        return response

    def current_user(authorization: Annotated[str | None, Header()] = None) -> str:
        user = authenticate(authorization, settings.api_key_hashes)
        if user is None:
            raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "Bearer"})
        if not limiter.allow(user):
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": "60"})
        return user

    User = Annotated[str, Depends(current_user)]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/documents", response_model=list[DocumentSummary])
    def list_documents(user: User):
        return [DocumentSummary(id=d.id, title=d.title, owner=d.owner) for d in store.readable_by(user)]

    @app.get("/v1/documents/{doc_id}", response_model=DocumentOut)
    def get_document(user: User, doc_id: Annotated[str, Path(pattern=DOC_ID)]):
        doc = store.get_for_user(doc_id, user)
        if doc is None:  # same answer for "missing" and "not yours" (no ID enumeration)
            raise HTTPException(404, "document not found")
        return DocumentOut(id=doc.id, title=doc.title, owner=doc.owner, body=doc.body)

    @app.get("/v1/search", response_model=list[DocumentSummary])
    def search(user: User, q: Annotated[str, Query(min_length=1, max_length=100)]):
        return [DocumentSummary(id=d.id, title=d.title, owner=d.owner) for d in store.search_titles(user, q)]

    @app.post("/v1/ask", response_model=AskResponse)
    def ask(user: User, body: AskRequest):
        question = body.question.strip()
        if len(question) > settings.max_question_chars:
            raise HTTPException(422, f"question longer than {settings.max_question_chars} characters")
        flagged = looks_like_injection(question)
        if flagged and settings.input_guard:
            audit.info(json.dumps({"event": "ask_rejected", "user": user, "reason": "prompt_injection_suspected"}))
            raise HTTPException(400, "question rejected by prompt-injection filter")

        # Authorization happens here, before retrieval: the model only ever sees this user's documents.
        chunks = retrieve(question, store.readable_by(user), settings.top_k)
        excluded: list[str] = []
        if settings.context_guard:  # indirect prompt injection planted in a shared document
            excluded = sorted({c.doc_id for c in chunks if looks_like_injection(c.text)})
            chunks = [c for c in chunks if c.doc_id not in excluded]
        allowed_ids = {c.doc_id for c in chunks}

        canary = new_canary()
        system = build_system_prompt(canary)
        raw = model.complete(system, build_user_prompt(question, chunks), settings.max_output_tokens)

        if tool := _TOOL_CALL.match(raw.strip()):
            try:
                raw = f"The result is {safe_calc(tool.group(1)):g}."
            except UnsafeExpression:
                raw = "I can only evaluate simple arithmetic."

        actions: list[str] = []
        answer = raw
        if settings.output_guard:
            verdict = check_output(raw, canary=canary, system_prompt=system, allowed_doc_ids=allowed_ids)
            actions = verdict.reasons
            answer = "The response was withheld by the output filter." if verdict.blocked else verdict.text
        citations = sorted({c for c in re.findall(r"\[([a-z0-9\-]+)\]", answer) if c in allowed_ids})
        audit.info(
            json.dumps(
                {
                    "event": "ask",
                    "user": user,
                    "question_chars": len(question),
                    "context_docs": sorted(allowed_ids),
                    "excluded_docs": excluded,
                    "output_actions": actions,
                    "model": model.name,
                }
            )
        )
        return AskResponse(
            answer=answer,
            citations=citations,
            model=model.name,
            guard=GuardReport(input_flagged=flagged, excluded_documents=excluded, output_actions=actions),
        )

    return app


def app_from_env() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return create_app()
