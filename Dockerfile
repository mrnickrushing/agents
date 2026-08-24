FROM python:3.11-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /build/
COPY agents /build/agents
RUN pip install --prefix=/install --no-cache-dir .

FROM python:3.11-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 agents

COPY --from=builder /install /usr/local
USER agents

ENTRYPOINT ["agents"]
CMD ["--help"]
