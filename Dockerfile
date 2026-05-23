FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY pyproject.toml README.md /app/
COPY scanner /app/scanner
COPY templates /app/templates
COPY policies /app/policies
COPY main.py /app/main.py

RUN pip install --no-cache-dir .

ENTRYPOINT ["python", "main.py"]
