# Production-ready Tor+Proxychains reconnaissance container
FROM debian:bookworm-slim

# Build arguments
ARG DEBIAN_FRONTEND=noninteractive

# Environment variables
ENV TOR_TIMEOUT_SECS=60 \
    LEAK_TEST_URL="https://ipinfo.io/ip" \
    RESULTS_DIR="/results" \
    PATH="/usr/local/bin:${PATH}"

# Install minimal required packages and remove cache in single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    proxychains4 \
    nmap \
    curl \
    dnsutils \
    netcat-openbsd \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user for scanning
RUN useradd -m -u 1000 -s /bin/bash scanner && \
    mkdir -p /results /home/scanner/.tor && \
    chown -R scanner:scanner /results /home/scanner

# Copy configuration and scripts
COPY --chown=scanner:scanner proxychains.conf /etc/proxychains4.conf
COPY --chown=scanner:scanner --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=scanner:scanner --chmod=755 check_leak.sh /usr/local/bin/check_leak.sh
COPY --chown=scanner:scanner --chmod=755 scan_wrapper.sh /usr/local/bin/scan_wrapper.sh
COPY --chown=scanner:scanner --chmod=755 internal_scan.sh /usr/local/bin/internal_scan.sh

# Configure Tor for container use
RUN echo "DataDirectory /home/scanner/.tor" >> /etc/tor/torrc && \
    echo "SOCKSPort 127.0.0.1:9050" >> /etc/tor/torrc && \
    echo "Log notice stdout" >> /etc/tor/torrc && \
    chown -R scanner:scanner /etc/tor /var/log/tor /var/lib/tor

# Switch to non-root user
USER scanner
WORKDIR /home/scanner

# No exposed ports - security by design
EXPOSE 0

# Healthcheck disabled - ephemeral container
HEALTHCHECK NONE

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
