# syntax=docker/dockerfile:1

# ---- Builder stage: install dependencies into an isolated venv ----
FROM python:3.12-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Pinned, explicit deps -- matches what's actually imported across app/.
# If pyproject.toml is later set up as a proper PEP 621 installable
# package (per the step-11 hygiene checklist), swap this block for
# `COPY pyproject.toml ./` + `pip install .` so the Dockerfile and
# pyproject.toml can't drift out of sync.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        "fastapi>=0.115,<1.0" \
        "uvicorn[standard]>=0.32,<1.0" \
        "pydantic>=2.9,<3.0" \
        "pyyaml>=6.0,<7.0"

# ---- Runtime stage: slim image, no compilers/build toolchain ----
FROM python:3.12-slim AS runtime

RUN useradd --create-home --uid 1000 appuser
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Only what the API actually needs at runtime -- no tests/, no CLI,
# no Streamlit UI in this image.
COPY app ./app
COPY policy.yaml ./policy.yaml

USER appuser

EXPOSE 8000

# Hits /policy, per the repo hygiene checklist -- also confirms
# policy.yaml loaded successfully at startup, not just that the
# process is alive.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/policy')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]