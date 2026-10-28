# S2/C-a 수신 Sink (P2) — 순수 stdlib, 외부 의존성 없음.
# Sink A/B는 이 한 이미지를 SINK_ROLE 환경변수로만 구분해 띄운다.
FROM python:3.12-slim

WORKDIR /app
COPY sink_server.py /app/sink_server.py

ENV PYTHONUNBUFFERED=1 \
    SINK_HOST=0.0.0.0 \
    SINK_PORT=8080

EXPOSE 8080
CMD ["python", "/app/sink_server.py"]
