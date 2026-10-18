# Network Observer - Enricher (#5)
# Zeek conn.log -> Canonical Network Event v1.0
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enricher/ /app/enricher/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/enricher

CMD ["python", "/app/enricher/main.py"]
