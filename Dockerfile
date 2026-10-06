# Cyber Audit — external security scanner (lite + deep profiles)
# Debian slim + nmap + ssh-audit + nuclei + nikto + testssl.sh + whatweb + dns tools.
FROM debian:bookworm-slim

ARG NUCLEI_VERSION=3.3.7

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        nmap \
        openssh-client \
        ca-certificates \
        curl \
        unzip \
        git \
        perl \
        nikto \
        whatweb \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# ScoutSuite — multi-cloud (AWS/Azure/GCP) configuration audit, read-only.
# Installed into its own venv to avoid clashing with the system Python.
RUN python3 -m venv /opt/scoutsuite \
    && /opt/scoutsuite/bin/pip install --no-cache-dir ScoutSuite \
    && ln -s /opt/scoutsuite/bin/ScoutSuite /usr/local/bin/ScoutSuite

# ssh-audit (single-file script)
RUN git clone --depth 1 https://github.com/jtesta/ssh-audit.git /opt/ssh-audit \
    && ln -s /opt/ssh-audit/ssh-audit.py /usr/local/bin/ssh-audit \
    && chmod +x /opt/ssh-audit/ssh-audit.py

# testssl.sh (full TLS/cipher/cert audit)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /opt/testssl.sh/testssl.sh

# nuclei (template-based CVE/misconfig engine; templates auto-update on first run)
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

WORKDIR /app
COPY audit.py selftest.py ./
COPY config/ ./config/

# Non-root runtime user.
RUN useradd -r -u 10001 auditor && mkdir -p /app/out && chown -R auditor /app/out
USER auditor

ENTRYPOINT ["python3", "/app/audit.py"]
CMD ["--config", "/app/config/example.config.json"]
