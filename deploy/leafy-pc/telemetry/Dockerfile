# Candidate only. Supply a reviewed immutable image digest at build time.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY exporter.py /app/exporter.py
USER 0
ENTRYPOINT ["python", "-B", "/app/exporter.py"]
