FROM kalilinux/kali-rolling

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# System tools + Python for building the venv
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    nmap \
    nikto \
    gobuster \
    whois \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Isolated venv — no Debian package conflicts
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip wheel

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/
COPY data/ ./data/

# Install into the venv (no --break-system-packages needed)
RUN pip install ".[web]"

# Non-root user
RUN useradd -m -u 1000 whaxon && chown -R whaxon:whaxon /app
USER whaxon

EXPOSE 5001

CMD ["gunicorn", \
     "--bind", "0.0.0.0:5001", \
     "--workers", "2", \
     "--access-logfile", "-", \
     "whaxon.interfaces.web.server:create_app_factory()"]
