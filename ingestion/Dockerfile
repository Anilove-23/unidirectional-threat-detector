FROM python:3.12-slim-bookworm

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    zeek \
    tshark \
    hping3 \
    iperf3 \
    ethtool \
    iproute2 \
    net-tools \
    tcpdump \
    libpcap-dev \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Allow tshark to run as non-root inside the container
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" \
    | debconf-set-selections \
    && dpkg-reconfigure -f noninteractive wireshark-common \
    && usermod -a -G wireshark root 2>/dev/null || true

WORKDIR /app

# ── Python deps ────────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────────────────────
COPY . .

# Make NIC lockdown script executable
RUN chmod +x capture/nic_lockdown.sh

# Expose metrics + health port
EXPOSE 9101

# ── Health check ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:9101/health || exit 1

# ── Default: simulation mode (safe non-root default) ──────────────────────────
# Override RUN_MODE=hardware for production deployments
ENV RUN_MODE=simulation
ENV CAPTURE_MODE=loopback
ENV CAPTURE_INTERFACE=lo

CMD ["python", "main.py"]
