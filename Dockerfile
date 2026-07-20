# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PORT=8787 \
    SLPROV2_DB=/data/slprov2_auth.db

RUN mkdir -p /data
COPY server.py admin_cli.py ./
COPY static ./static

EXPOSE 8787
VOLUME ["/data"]

# First boot prints bootstrap admin if none exists
CMD ["python", "server.py"]
