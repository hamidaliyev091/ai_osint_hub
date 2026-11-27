# Multi-stage non-root production image for AI OSINT Hub
ARG PYTHON_VERSION=3.12-slim

FROM python:${PYTHON_VERSION} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
RUN python -m pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml requirements.txt README.md ./
COPY hub ./hub

RUN python -m build --wheel --outdir /wheels


FROM python:${PYTHON_VERSION} AS core

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AI_OSINT_HUB_HOME=/data

RUN groupadd --gid 10001 osint \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/osint --shell /usr/sbin/nologin osint \
    && mkdir -p /data /home/osint/.ai_osint_hub \
    && chown -R 10001:10001 /data /home/osint

COPY --from=builder /wheels /tmp/wheels
RUN python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

VOLUME ["/data"]
WORKDIR /data
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/tools', timeout=3).read()"]

CMD ["ai-osint-hub", "serve", "--host", "0.0.0.0", "--port", "8000"]


FROM core AS full

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        gobuster \
        hashcat \
        hydra \
        nmap \
        tesseract-ocr \
        whatweb \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir \
        holehe \
        maigret \
        h8mail \
        sherlock-project \
        ghunt \
        "git+https://github.com/laramies/theHarvester.git@4.11.1"

USER 10001:10001
