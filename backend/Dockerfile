# =============================================================================
# IntelliVAPT Backend — Dockerfile
# Downloads pre-built binaries from GitHub releases (no Go compilation needed)
# =============================================================================

FROM python:3.12-slim-bookworm

# Install system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    perl \
    libnet-ssleay-perl \
    curl \
    ca-certificates \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Download ProjectDiscovery tools using GitHub API to resolve correct URLs
# --- Subfinder ---
RUN DOWNLOAD_URL=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip$")) | .browser_download_url') \
    && echo "Downloading subfinder from: $DOWNLOAD_URL" \
    && curl -sL "$DOWNLOAD_URL" -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /tmp/subfinder_dir \
    && find /tmp/subfinder_dir -name subfinder -type f | head -1 | xargs -I{} cp {} /usr/bin/subfinder \
    && chmod +x /usr/bin/subfinder \
    && cp /usr/bin/subfinder /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder.zip /tmp/subfinder_dir

# --- HTTPX ---
RUN DOWNLOAD_URL=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip$")) | .browser_download_url') \
    && echo "Downloading httpx from: $DOWNLOAD_URL" \
    && curl -sL "$DOWNLOAD_URL" -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip -d /tmp/httpx_dir \
    && find /tmp/httpx_dir -name httpx -type f | head -1 | xargs -I{} cp {} /usr/bin/httpx \
    && chmod +x /usr/bin/httpx \
    && cp /usr/bin/httpx /usr/local/bin/httpx \
    && rm -rf /tmp/httpx.zip /tmp/httpx_dir

# --- Nuclei ---
RUN DOWNLOAD_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip$")) | .browser_download_url') \
    && echo "Downloading nuclei from: $DOWNLOAD_URL" \
    && curl -sL "$DOWNLOAD_URL" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_dir \
    && find /tmp/nuclei_dir -name nuclei -type f | head -1 | xargs -I{} cp {} /usr/bin/nuclei \
    && chmod +x /usr/bin/nuclei \
    && cp /usr/bin/nuclei /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_dir

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Restore ProjectDiscovery httpx binary if pip created an httpx CLI script
RUN cp /usr/bin/httpx /usr/local/bin/httpx && chmod +x /usr/local/bin/httpx

# Verify all security tools AFTER pip install
RUN echo "=== Tool Verification ===" \
    && subfinder -version \
    && httpx -version \
    && nuclei -version \
    && nmap --version | head -1 \
    && echo "=== All tools OK ==="

# Copy application code
COPY app ./app

# Create storage directories
RUN mkdir -p /app/storage/reports

# Create non-root user
RUN useradd -m appuser && chown -R appuser /app /app/storage
USER appuser

# Update Nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
