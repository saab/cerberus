# uv preinstalled on a Debian base that also has python3 + curl available.
FROM ghcr.io/astral-sh/uv:debian

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests
COPY run_e2e.sh .
RUN chmod +x run_e2e.sh

ENTRYPOINT ["./run_e2e.sh"]
