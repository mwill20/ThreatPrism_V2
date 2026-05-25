FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    THREATPRISM_ENV=demo \
    DATABASE_URL=sqlite:////app/data/threatprism.db \
    API_AUTH_MODE=demo_key \
    DEMO_API_KEYS=demo-analyst-key:demo_analyst:analyst,demo-engineer-key:demo_engineer:engineer,demo-manager-key:demo_manager:manager_grc,demo-legal-key:demo_legal:legal_privacy,demo-audit-key:demo_audit:audit_debug,demo-admin-key:demo_admin:admin \
    THREATPRISM_AUTH_REQUIRED=true \
    THREATPRISM_LOCAL_DEV_ACK=false \
    LLM_PROVIDER=deterministic_demo \
    ALLOW_REAL_ACTIONS=false \
    MAX_REQUEST_BODY_BYTES=262144 \
    CASE_POST_RATE_LIMIT_PER_MINUTE=60 \
    TRIAGE_CONCURRENCY_LIMIT=4

WORKDIR /app

RUN groupadd --system threatprism \
    && useradd --system --gid threatprism --home-dir /app --shell /usr/sbin/nologin threatprism

COPY requirements-lock.txt requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements-lock.txt

COPY src ./src
COPY examples ./examples
COPY README.md RUNBOOK.md ./

RUN mkdir -p /app/data \
    && chown -R threatprism:threatprism /app

USER threatprism
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).read()"

CMD ["python", "-m", "uvicorn", "threatprism.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
