FROM ollama/ollama:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY sandbox/entrypoint.py /app/entrypoint.py
COPY prompts/naive.txt /app/naive.txt

RUN chmod +x /app/entrypoint.py

# Model cache lives in a named volume — mount /root/.ollama externally
VOLUME ["/root/.ollama"]

# I/O volume: input.txt goes in, logs come out
VOLUME ["/sandbox"]

ENTRYPOINT ["python3", "/app/entrypoint.py"]
