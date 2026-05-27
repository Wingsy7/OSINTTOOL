FROM python:3.14-slim

WORKDIR /app
COPY osint_harvester.py /app/osint_harvester.py

RUN adduser --disabled-password --gecos "" appuser
RUN mkdir -p /app/reports && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "/app/osint_harvester.py"]
