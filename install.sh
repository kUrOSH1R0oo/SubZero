#!/bin/bash
# ==============================================
# SubZero Installer
# ==============================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYN}[INFO]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
success() { echo -e "${GRN}[OK]${NC} $*"; }

if (( EUID != 0 )); then
	error "This script requires root privileges. Use: sudo $0"
	exit 1
fi
success "Running with root privileges"

declare -A PKG_INSTALL
PKG_INSTALL=(
	[apt]="apt install -y"
 	[apt-get]="apt-get install -y"
    	[dnf]="dnf install -y"
    	[yum]="yum install -y"
    	[pacman]="pacman -Sy --noconfirm"
)

PKG_MANAGER=""
for mgr in "${!PKG_INSTALL[@]}"; do
	if command -v "$mgr" &>/dev/null; then
		PKG_MANAGER="$mgr"
		break
	fi
done

if [[ -z "$PKG_MANAGER" ]]; then
	error "No supportd package manager found (apt, yum, dnf, pacman)."
	exit 1
fi
success "Detected package manager: $PKG_MANAGER"

if ! command -v python3 &>/dev/null; then
	log "Installing python3..."
	${PKG_INSTALL[$PKG_MANAGER]} python3
else
	success "python3 already installed"
fi

if ! command -v pip3 &>/dev/null; then
        log "Installing pip3..."
        ${PKG_INSTALL[$PKG_MANAGER]} python3-pip
else
        success "pip3 already installed"
fi

REQ_PKGS=(numpy passlib argon2_cffi pycryptodome cryptography python-camellia rich pikepdf)

log "Installing required libraries: ${REQ_PKGS[*]}"
pip3 install --upgrade "${REQ_PKGS[@]}" --break-system-packages
success "All required libraries installed"

TARGET="subzero.py"
LINK="/usr/local/bin/subzero"

if [[ ! -f "$TARGET" ]]; then
	error "$TARGET not found in current directory ($(pwd))"
	exit 1
fi

ln -sf "$(realpath "$TARGET")" "$LINK"
chmod +x "$TARGET"
success "Symlink created: $LINK -> $(realpath "$TARGET")"

printf "%s\n"
cat <<'BANNER'
   _____       __ _____
  / ___/__  __/ //__  /  ___  _________
  \__ \/ / / / __ \/ /  / _ \/ ___/ __ \
 ___/ / /_/ / /_/ / /__/  __/ /  / /_/ /
/____/\__,_/_.___/____/\___/_/   \____/
                        - Kur0Sh1r0
BANNER
printf "%s\n"

success "Installation complete. Type 'subzero' to run from anywhere."
