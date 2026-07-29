#!/usr/bin/env bash
# RE-super-agent install script (Linux / macOS / WSL / Git Bash).
# Usage:
#   ./install.sh core   # minimal: Python deps + r2 + YARA + Docker image (core)
#   ./install.sh full   # everything: + Ghidra, angr, Qiling, Frida, debuggers, capa, binwalk
#   ./install.sh check  # report what is available / missing
set -euo pipefail

TIER="${1:-core}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info()  { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

OS_TAG="$(uname -s)"
if [[ "$OS_TAG" == Darwin* ]]; then
  PM_INSTALL="brew install"
elif have apt-get; then
  PM_INSTALL="sudo apt-get update && sudo apt-get install -y"
elif have dnf; then
  PM_INSTALL="sudo dnf install -y"
elif have pacman; then
  PM_INSTALL="sudo pacman -S --noconfirm"
else
  PM_INSTALL="echo"
  warn "Unrecognized package manager; skipping system packages. Install tools manually."
fi

check_tool() {
  local name="$1"
  if have "$name"; then ok "found: $name"; else warn "missing: $name"; MISSING+=("$name"); fi
}

install_core() {
  info "Installing core (Python deps + r2 + YARA + Docker image)."
  python -m pip install -e ".[dev]"
  # radare2 / rizin
  if ! have r2 && ! have rizin; then
    info "Installing radare2 (or rizin) via system package / script ..."
    $PM_INSTALL radare2 || true
    if ! have r2; then
      git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/r2 || true
      (cd /tmp/r2 && sys/install.sh) || warn "radare2 install failed; install manually"
    fi
  fi
  # YARA (python wheel usually bundles engine, but system lib helps)
  $PM_INSTALL yara || true
  build_docker core
}

install_full() {
  install_core
  info "Installing full RE stack (Ghidra, angr, Qiling, Frida, debuggers, capa, binwalk)."
  python -m pip install -e ".[full]"
  # Ghidra (needs JDK)
  $PM_INSTALL default-jdk || true
  if ! have ghidraRun && [[ ! -d /opt/ghidra ]]; then
    info "Downloading Ghidra (manual step may be needed for license/URL)."
    warn "Install Ghidra from https://github.com/NationalSecurityAgency/ghidra/releases and set engines.ghidra.install_path"
  fi
  # Frida system bits
  $PM_INSTALL frida || true
  # Debugger
  $PM_INSTALL gdb || true
  # binwalk system deps
  $PM_INSTALL binwalk || true
  # capa
  python -m pip install capa || true
  build_docker full
}

build_docker() {
  local tier="${1:-core}"
  if have docker; then
    info "Building re-agent:$tier sandbox image ..."
    docker build --target "$tier" -t "re-agent:$tier" -f Dockerfile . \
      || warn "Docker build failed; sandbox features will be unavailable."
  else
    warn "docker not found; sandbox will run in static-only fallback. Install Docker to enable dynamic exec."
  fi
}

check() {
  MISSING=()
  info "Checking tool availability:"
  for t in python pip git r2 rizin yara frida gdb angr qiling docker; do
    case "$t" in
      r2|rizin) check_tool "$t" ;;
      *) check_tool "$t" ;;
    esac
  done
  if [[ ${#MISSING[@]} -eq 0 ]]; then ok "all checked tools present."; else
    warn "missing: ${MISSING[*]}"; fi
}

case "$TIER" in
  core) install_core ;;
  full) install_full ;;
  check) check ;;
  *) err "Usage: $0 {core|full|check}"; exit 1 ;;
esac

ok "Done ($TIER)."
