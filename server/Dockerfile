FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCANVAULT_DATA=/data \
    PUID=10001 \
    PGID=10001 \
    FORWARDED_ALLOW_IPS=127.0.0.1,::1 \
    SCANVAULT_LOCAL_BACKUP_ROOT=/backups

WORKDIR /srv
# Tesseract reads scanned lab reports and photos of them (LabsVault). It runs
# locally; set SCANVAULT_OCR=0 at build time to leave it out (~30 MB).
ARG SCANVAULT_OCR=1
RUN if [ "$SCANVAULT_OCR" = "1" ]; then apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng && rm -rf /var/lib/apt/lists/*; fi
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tools ./tools
COPY docker/entrypoint.sh /usr/local/bin/scanvault-entrypoint

RUN mkdir -p /data /backups
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health').status==200 else 1)"

# Starts as root only to fix /data ownership, then drops to PUID:PGID.
# X-Forwarded-* headers are only trusted from FORWARDED_ALLOW_IPS (set it to
# your reverse proxy's address, e.g. the Docker bridge 172.16.0.0/12).
ENTRYPOINT ["scanvault-entrypoint"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
