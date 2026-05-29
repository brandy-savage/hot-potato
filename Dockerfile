# Pinned digest — update after reviewing release notes.
# ollama/ollama 0.6.x pulled 2026-05-07; run `docker pull ollama/ollama` and update digest to upgrade.
FROM ollama/ollama@sha256:6077dbbd6508dce8973f8b91c30d8026b1279ab0483e15f0dfad469dba676c2f

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    jq \
    libfaketime \
    && rm -rf /var/lib/apt/lists/*

# libfaketime intercepts clock syscalls — set FAKETIME env to override system time.
# Example: docker run -e FAKETIME="@2026-01-01 02:00:00" ...
# The entrypoint also reads HP_FAKE_EPOCH (unix timestamp) for the get_system_time() tool.
ENV FAKETIME_NO_CACHE=1

COPY sandbox/entrypoint.py /app/entrypoint.py
COPY prompts/naive.txt /app/naive.txt
COPY prompts/claude_code.txt /app/claude_code.txt
COPY sandbox/skills/ /app/skills/

RUN chmod +x /app/entrypoint.py

# Model cache lives in a named volume — mount /root/.ollama externally
VOLUME ["/root/.ollama"]

# I/O volume: input.txt goes in, logs come out
VOLUME ["/sandbox"]

ENTRYPOINT ["python3", "/app/entrypoint.py"]
