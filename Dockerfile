# syntax=docker/dockerfile:1
# Hardened image. Runtime: Chainguard (Wolfi) Python, which has no shell or package manager, runs
# as UID 65532 and is rebuilt daily, so OS-level CVEs get fixed quickly. Both stages are pinned
# by digest and must use the same Python version. Dependabot (docker) proposes digest updates.
# Run with: --read-only --cap-drop ALL --security-opt no-new-privileges (see Makefile / compose).

FROM cgr.dev/chainguard/python:latest-dev@sha256:768ee36ee9f4b8c882634c07d0b889425bc8e100886a3f742b83b1c647cc2d4b AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-compile --require-hashes --no-deps --only-binary=:all: --target /build/deps -r requirements.txt

FROM cgr.dev/chainguard/python:latest@sha256:f522a16f34c8aa60f831e6476e396ef3951830a1b9059d19bc531a544d0f1579
WORKDIR /app
COPY --from=build /build/deps /app/deps
COPY src/ /app/src/
COPY data/ /app/data/
ENV PYTHONPATH=/app/deps:/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOCQA_DATA_DIR=/app/data
USER 65532:65532
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "uvicorn", "docqa.api:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
