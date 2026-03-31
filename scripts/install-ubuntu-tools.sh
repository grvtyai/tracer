#!/usr/bin/env bash

set -euo pipefail

log() {
  printf '[tracer-install] %s\n' "$*"
}

warn() {
  printf '[tracer-install][warn] %s\n' "$*" >&2
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[tracer-install][error] missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

append_path_once() {
  local profile_file="$1"
  local line="$2"

  touch "$profile_file"
  if ! grep -Fqx "$line" "$profile_file"; then
    printf '\n%s\n' "$line" >>"$profile_file"
  fi
}

install_or_upgrade_pipx_pkg() {
  local package_name="$1"

  if python3 -m pipx list --short 2>/dev/null | grep -Fxq "$package_name"; then
    log "Upgrading $package_name via pipx"
    python3 -m pipx upgrade "$package_name"
  else
    log "Installing $package_name via pipx"
    python3 -m pipx install "$package_name"
  fi
}

if [[ "${EUID}" -eq 0 ]]; then
  warn "Bitte das Skript als normaler Benutzer ausfuehren, nicht direkt als root."
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  warn "Dieses Skript erwartet Ubuntu."
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  warn "Unterstuetzt ist Ubuntu. Erkannt wurde: ${ID:-unknown}"
  exit 1
fi

require_cmd sudo
require_cmd curl
require_cmd git

UBUNTU_VERSION="${VERSION_ID:-}"
UBUNTU_DIST_TAG="xUbuntu_${UBUNTU_VERSION}"
GO_VERSION_RAW="$(curl -fsSL https://go.dev/VERSION?m=text)"
GO_VERSION="$(printf '%s\n' "$GO_VERSION_RAW" | head -n1 | tr -d '\r')"
GO_TARBALL_URL="https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz"
GO_TARBALL="$(mktemp /tmp/go-toolchain.XXXXXX.tar.gz)"
WORKDIR="$(mktemp -d /tmp/tracer-tools.XXXXXX)"
PATH_LINE='export PATH=/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:/opt/zeek/bin:$PATH'
ZEEK_LIST_FILE="/etc/apt/sources.list.d/security:zeek.list"
ZEEK_KEY_FILE="/etc/apt/trusted.gpg.d/security_zeek.gpg"
SHARPHOUND_DEST="${HOME}/.local/share/tracer/sharphound"
SHARPHOUND_ZIP="${SHARPHOUND_DEST}/SharpHound-latest.zip"
SCAMPER_APT_REPOSITORY="${SCAMPER_APT_REPOSITORY:-ppa:matthewluckie/scamper}"
SCAMPER_PPA_SUPPORTED=0

case "${UBUNTU_VERSION}" in
  "20.04"|"22.04"|"24.04")
    SCAMPER_PPA_SUPPORTED=1
    ;;
esac

cleanup() {
  rm -f "$GO_TARBALL"
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

log "Installing base Ubuntu packages"
sudo apt-get update
sudo apt-get install -y \
  apt-transport-https \
  arp-scan \
  build-essential \
  ca-certificates \
  curl \
  git \
  gnupg \
  jq \
  libpcap-dev \
  lsb-release \
  make \
  nmap \
  pipx \
  python3 \
  python3-pip \
  python3-venv \
  software-properties-common \
  unzip \
  zmap

log "Installing Go from ${GO_TARBALL_URL}"
curl -fsSL "$GO_TARBALL_URL" -o "$GO_TARBALL"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "$GO_TARBALL"

mkdir -p "${HOME}/go/bin" "${HOME}/.local/bin" "$SHARPHOUND_DEST"
append_path_once "${HOME}/.profile" "$PATH_LINE"
append_path_once "${HOME}/.bashrc" "$PATH_LINE"
export PATH="/usr/local/go/bin:${HOME}/go/bin:${HOME}/.local/bin:/opt/zeek/bin:${PATH}"

log "Ensuring pipx PATH helpers"
python3 -m pipx ensurepath >/dev/null || true

log "Installing ProjectDiscovery tools with Go"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

if command -v setcap >/dev/null 2>&1; then
  sudo setcap cap_net_raw,cap_net_admin=eip "${HOME}/go/bin/naabu" || true
fi

log "Installing zgrab2 from source"
git clone --depth 1 https://github.com/zmap/zgrab2.git "${WORKDIR}/zgrab2"
(
  cd "${WORKDIR}/zgrab2"
  make
  install -m 0755 zgrab2 "${HOME}/.local/bin/zgrab2"
)

if [[ "$SCAMPER_PPA_SUPPORTED" -eq 1 ]]; then
  log "Installing scamper from Ubuntu PPA"
  sudo add-apt-repository -y "$SCAMPER_APT_REPOSITORY"
  sudo apt-get update
  if ! sudo apt-get install -y scamper scamper-utils; then
    warn "scamper-utils war nicht verfuegbar; installiere nur scamper."
    sudo apt-get install -y scamper
  fi
else
  warn "Scamper-PPA ist nur fuer Ubuntu 20.04/22.04/24.04 direkt hinterlegt. Bitte manuell nachziehen."
fi

log "Installing Zeek from official OBS repository"
echo "deb https://download.opensuse.org/repositories/security:/zeek/${UBUNTU_DIST_TAG}/ /" | sudo tee "$ZEEK_LIST_FILE" >/dev/null
curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/${UBUNTU_DIST_TAG}/Release.key" \
  | gpg --dearmor \
  | sudo tee "$ZEEK_KEY_FILE" >/dev/null
sudo apt-get update
if ! sudo apt-get install -y zeek; then
  warn "Zeek Paket 'zeek' nicht verfuegbar; versuche 'zeek-lts'."
  sudo apt-get install -y zeek-lts
fi

log "Installing Python CLI tooling"
install_or_upgrade_pipx_pkg impacket
install_or_upgrade_pipx_pkg ldapdomaindump

log "Downloading latest SharpHound release zip"
SHARPHOUND_ASSET_URL="$(
  curl -fsSL https://api.github.com/repos/SpecterOps/SharpHound/releases/latest \
    | jq -r '.assets[] | select(.name | endswith(".zip")) | .browser_download_url' \
    | head -n1
)"

if [[ -n "$SHARPHOUND_ASSET_URL" && "$SHARPHOUND_ASSET_URL" != "null" ]]; then
  curl -fsSL "$SHARPHOUND_ASSET_URL" -o "$SHARPHOUND_ZIP"
else
  warn "Konnte keine SharpHound-ZIP in der aktuellen Release finden."
fi

log "Installation abgeschlossen"
log "Starte jetzt idealerweise: bash scripts/verify-ubuntu-tools.sh"
