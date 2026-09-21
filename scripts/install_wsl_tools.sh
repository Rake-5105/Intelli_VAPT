#!/usr/bin/env bash
# ============================================================================
# IntelliVAPT — WSL Security Tool Installer
#
# Run this script inside WSL to install all required security tools:
#   wsl -e bash scripts/install_wsl_tools.sh
#
# Supports Ubuntu/Debian-based distributions.
# ============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  IntelliVAPT — WSL Security Tool Installer${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
installed() {
    command -v "$1" &>/dev/null
}

install_go_tool() {
    local name="$1"
    local repo="$2"
    local version="${3:-latest}"

    if installed "$name"; then
        echo -e "  ${GREEN}✓${NC} $name already installed: $(which $name)"
        return
    fi

    echo -e "  ${YELLOW}↓${NC} Installing $name from $repo..."
    if installed go; then
        go install "${repo}@${version}" 2>/dev/null && echo -e "  ${GREEN}✓${NC} $name installed via go install" && return
    fi

    # Fallback: download pre-built binary from GitHub releases
    echo -e "  ${YELLOW}↓${NC} Downloading $name binary from GitHub releases..."
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       echo -e "  ${RED}✗${NC} Unsupported architecture: $arch"; return 1 ;;
    esac

    local gh_repo
    gh_repo=$(echo "$repo" | sed 's|github.com/||' | sed 's|/v2/.*||' | sed 's|/cmd/.*||')

    local tmpdir
    tmpdir=$(mktemp -d)
    local latest_url="https://api.github.com/repos/${gh_repo}/releases/latest"
    local download_url

    download_url=$(curl -sL "$latest_url" | grep "browser_download_url" | grep "linux" | grep "$arch" | grep -v "sha256\|checksum" | head -1 | cut -d '"' -f 4)

    if [ -n "$download_url" ]; then
        curl -sL "$download_url" -o "${tmpdir}/${name}.zip"
        if file "${tmpdir}/${name}.zip" | grep -q "Zip"; then
            unzip -q "${tmpdir}/${name}.zip" -d "${tmpdir}" 2>/dev/null || true
        else
            # Might be a tar.gz
            mv "${tmpdir}/${name}.zip" "${tmpdir}/${name}.tar.gz"
            tar xzf "${tmpdir}/${name}.tar.gz" -C "${tmpdir}" 2>/dev/null || true
        fi
        find "${tmpdir}" -name "$name" -type f -executable | head -1 | xargs -I{} sudo cp {} /usr/local/bin/
        sudo chmod +x "/usr/local/bin/$name" 2>/dev/null || true
        rm -rf "$tmpdir"
        echo -e "  ${GREEN}✓${NC} $name installed to /usr/local/bin/"
    else
        echo -e "  ${RED}✗${NC} Could not find download for $name (try installing Go first)"
        rm -rf "$tmpdir"
    fi
}

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
echo -e "${CYAN}[1/4] Updating package lists and installing system tools...${NC}"
sudo apt-get update -qq
sudo apt-get install -y -qq nmap nikto whatweb curl unzip git golang-go 2>/dev/null || {
    echo -e "  ${YELLOW}!${NC} Some packages may not be available. Installing what we can..."
    sudo apt-get install -y -qq nmap curl unzip git 2>/dev/null || true
    sudo apt-get install -y -qq nikto 2>/dev/null || true
    sudo apt-get install -y -qq whatweb 2>/dev/null || true
    sudo apt-get install -y -qq golang-go 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 2. Go environment
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}[2/4] Configuring Go environment...${NC}"
export GOPATH="${HOME}/go"
export PATH="${PATH}:${GOPATH}/bin:/usr/local/go/bin"

# Add to profile for persistence
if ! grep -q 'GOPATH' ~/.bashrc 2>/dev/null; then
    echo 'export GOPATH="${HOME}/go"' >> ~/.bashrc
    echo 'export PATH="${PATH}:${GOPATH}/bin:/usr/local/go/bin"' >> ~/.bashrc
    echo -e "  ${GREEN}✓${NC} Go paths added to ~/.bashrc"
fi

if installed go; then
    echo -e "  ${GREEN}✓${NC} Go version: $(go version)"
else
    echo -e "  ${RED}✗${NC} Go not available. ProjectDiscovery tools will use binary downloads."
fi

# ---------------------------------------------------------------------------
# 3. ProjectDiscovery tools (Subfinder, HTTPX, Nuclei)
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}[3/4] Installing ProjectDiscovery security tools...${NC}"

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# Update Nuclei templates
if installed nuclei; then
    echo -e "  ${YELLOW}↓${NC} Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && echo -e "  ${GREEN}✓${NC} Nuclei templates updated" || true
fi

# ---------------------------------------------------------------------------
# 4. Verification
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}[4/4] Verification Report${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

TOOLS=("nmap" "subfinder" "httpx" "nuclei" "nikto" "whatweb")
ALL_OK=true

for tool in "${TOOLS[@]}"; do
    if installed "$tool"; then
        path=$(which "$tool")
        echo -e "  ${GREEN}✓${NC} ${tool} → ${path}"
    else
        echo -e "  ${RED}✗${NC} ${tool} — NOT FOUND"
        ALL_OK=false
    fi
done

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if $ALL_OK; then
    echo -e "${GREEN}All tools installed successfully! IntelliVAPT is ready for real scanning.${NC}"
else
    echo -e "${YELLOW}Some tools are missing. You can retry or install them manually.${NC}"
fi
echo ""
