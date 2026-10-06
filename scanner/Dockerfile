FROM aquasec/trivy:0.74.0 AS trivy

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/cache/trivy \
    WORK_DIR=/work

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py .

RUN useradd --create-home scanner \
    && mkdir -p /cache/trivy /work \
    && chown scanner:scanner /cache/trivy /work
USER scanner

CMD ["python", "run.py"]
