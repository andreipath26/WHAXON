FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System tools that the catalog needs
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    gobuster \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install package with web extra
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/
COPY data/ ./data/
RUN pip install --upgrade pip wheel && pip install ".[web]"

# Non-root user
RUN useradd -m -u 1000 whaxon && chown -R whaxon:whaxon /app
USER whaxon

EXPOSE 5001

# Default: gunicorn serving the factory
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5001", \
     "--workers", "2", \
     "--access-logfile", "-", \
     "whaxon.interfaces.web.server:create_app_factory()"]
