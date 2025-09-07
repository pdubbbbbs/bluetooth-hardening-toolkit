#!/bin/bash

# ========================================================================
# Bluetooth Hardening Toolkit - Universal Installer
# ========================================================================
# Author: Philip S. Wright (@pdubbbbbs)
# License: MIT
# Description: One-line installer for all platforms
# ========================================================================

set -euo pipefail

readonly REPO_URL="https://github.com/pdubbbbbs/bluetooth-hardening-toolkit"
readonly INSTALL_DIR="/opt/bluetooth-hardening-toolkit"
readonly VERSION="2.0.0"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

check_requirements() {
    local os="$1"
    
    case "$os" in
        "linux")
            if ! command -v git >/dev/null 2>&1; then
                error "git is required but not installed"
                exit 1
            fi
            ;;
        "macos")
            if ! command -v git >/dev/null 2>&1; then
                error "git is required but not installed. Install Xcode Command Line Tools first."
                exit 1
            fi
            ;;
        "windows")
            if ! command -v git >/dev/null 2>&1; then
                error "git is required but not installed. Install Git for Windows first."
                exit 1
            fi
            ;;
        *)
            error "Unsupported operating system: $OSTYPE"
            exit 1
            ;;
    esac
}

install_toolkit() {
    local os="$1"
    
    log "Installing Bluetooth Hardening Toolkit v$VERSION..."
    
    # Clone or update repository
    if [[ -d "$INSTALL_DIR" ]]; then
        log "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull origin main
    else
        log "Downloading toolkit..."
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    
    cd "$INSTALL_DIR"
    
    # Make scripts executable
    find scripts -name "*.sh" -exec chmod +x {} \;
    
    case "$os" in
        "linux"|"macos")
            # Create symlinks
            log "Creating command-line shortcuts..."
            ln -sf "$INSTALL_DIR/scripts/linux/bt-harden-linux.sh" /usr/local/bin/bt-harden 2>/dev/null || true
            if [[ "$os" == "macos" ]]; then
                ln -sf "$INSTALL_DIR/scripts/macos/bt-harden-macos.sh" /usr/local/bin/bt-harden-macos 2>/dev/null || true
            fi
            ;;
    esac
    
    log "Installation complete!"
    echo ""
    echo -e "${PURPLE}=== Bluetooth Hardening Toolkit v$VERSION ===${NC}"
    echo -e "${CYAN}Installation directory: $INSTALL_DIR${NC}"
    echo ""
    echo -e "${YELLOW}Quick start commands:${NC}"
    
    case "$os" in
        "linux")
            echo -e "  ${GREEN}sudo bt-harden --disable-all${NC}                    # Complete hardening"
            echo -e "  ${GREEN}sudo $INSTALL_DIR/scripts/linux/bt-harden-linux.sh --help${NC}  # Show help"
            ;;
        "macos")
            echo -e "  ${GREEN}sudo bt-harden-macos --disable-all${NC}              # Complete hardening"
            echo -e "  ${GREEN}sudo $INSTALL_DIR/scripts/macos/bt-harden-macos.sh --help${NC}   # Show help"
            ;;
        "windows")
            echo -e "  ${GREEN}$INSTALL_DIR/scripts/windows/bt-harden-windows.ps1 -DisableAll${NC}  # Complete hardening"
            echo -e "  ${GREEN}$INSTALL_DIR/scripts/windows/bt-harden-windows.ps1 -Help${NC}        # Show help"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Documentation: $INSTALL_DIR/README.md${NC}"
    echo -e "${YELLOW}GitHub: $REPO_URL${NC}"
    echo ""
}

main() {
    echo -e "${PURPLE}"
    cat << 'EOF'
 ____  _            _              _   _     
|  _ \| |_   _  ___| |_ ___   ___ | |_| |__  
| |_) | | | | |/ _ \ __/ _ \ / _ \| __| '_ \ 
|  _ <| | |_| |  __/ || (_) | (_) | |_| | | |
|_| \_\_|\__,_|\___|\__\___/ \___/ \__|_| |_|
                                            
 _   _               _            _             
| | | | __ _ _ __ __| | ___ _ __ (_)_ __   __ _ 
| |_| |/ _` | '__/ _` |/ _ \ '_ \| | '_ \ / _` |
|  _  | (_| | | | (_| |  __/ | | | | | | | (_| |
|_| |_|\__,_|_|  \__,_|\___|_| |_|_|_| |_|\__, |
                                         |___/ 
 _____           _ _    _ _   
|_   _|__   ___ | | | _(_) |_ 
  | |/ _ \ / _ \| | |/ / | __|
  | | (_) | (_) | |   <| | |_ 
  |_|\___/ \___/|_|_|\_\_|\__|

EOF
    echo -e "${NC}"
    echo -e "${CYAN}Universal Installer for Bluetooth Security Hardening${NC}"
    echo -e "${WHITE}Protecting against BlueBorne and related attacks${NC}"
    echo ""
    
    local os=$(detect_os)
    log "Detected OS: $os"
    
    check_requirements "$os"
    
    # Check for root on Linux/macOS
    if [[ "$os" != "windows" && $EUID -ne 0 ]]; then
        error "This installer must be run as root (use sudo)"
        exit 1
    fi
    
    install_toolkit "$os"
    
    echo -e "${GREEN}🎉 Installation successful!${NC}"
    echo -e "${CYAN}Ready to harden Bluetooth security across your infrastructure.${NC}"
}

main "$@"
