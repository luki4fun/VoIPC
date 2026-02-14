#!/usr/bin/env bash
# VoIPC Linux (Ubuntu/Debian) development environment setup
# Installs system packages, Rust, Node.js, and runs npm install.
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
info() { echo -e "${YELLOW}[..]${NC} $*"; }
err()  { echo -e "${RED}[!!]${NC} $*"; }

echo -e "\n${CYAN}=== VoIPC Linux Setup ===${NC}"

# ── System packages ───────────────────────────────────────────────────────
info "Installing system dependencies (may prompt for sudo password)..."
sudo apt-get update -qq
sudo apt-get install -y \
  libavcodec-dev \
  libavformat-dev \
  libavfilter-dev \
  libavdevice-dev \
  libavutil-dev \
  libswscale-dev \
  libx265-dev \
  libclang-dev \
  libturbojpeg0-dev \
  nasm \
  libpipewire-0.3-dev \
  libgbm-dev \
  libasound2-dev \
  libssl-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev \
  curl \
  build-essential
ok "System packages installed"

# ── Rust ──────────────────────────────────────────────────────────────────
if command -v rustc &>/dev/null; then
    ok "Rust already installed ($(rustc --version))"
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    ok "Rust installed"
fi
export PATH="$HOME/.cargo/bin:$PATH"

# ── Node.js ───────────────────────────────────────────────────────────────
if command -v node &>/dev/null; then
    ok "Node.js already installed ($(node --version))"
else
    info "Installing Node.js via nvm..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
    nvm install --lts
    ok "Node.js installed ($(node --version))"
fi

# ── npm install ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
info "Running npm install in client/..."
cd "$SCRIPT_DIR/client"
npm install
ok "npm dependencies installed"

echo -e "\n${CYAN}=== Setup complete ===${NC}"
echo "Run:  ./dev.sh   (debug)  or  ./build.sh  (release)"
echo ""
