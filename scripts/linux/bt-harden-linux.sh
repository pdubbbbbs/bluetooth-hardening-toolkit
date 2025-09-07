#!/bin/bash

# ========================================================================
# Bluetooth Hardening Toolkit - Linux Edition
# ========================================================================
# Author: Philip S. Wright (@pdubbbbbs)
# License: MIT
# Description: Comprehensive Bluetooth hardening for Linux systems
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, SUSE, Alpine
# ========================================================================

set -euo pipefail

# Global variables
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/bt-hardening.log"
readonly BACKUP_DIR="/etc/bt-hardening-backup"
readonly CONFIG_FILE="/etc/bt-hardening.conf"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Default configuration
PROFILE="maximum"
DRY_RUN=false
QUIET=false
BACKUP=true
MONITORING=false

# ========================================================================
# Utility Functions
# ========================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$QUIET" == false ]]; then
        case "$level" in
            "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
            "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
            "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
            "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
            *)       echo -e "${WHITE}[LOG]${NC} $message" ;;
        esac
    fi
    
    echo "$timestamp [$level] $message" >> "$LOG_FILE"
}

print_banner() {
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
    echo -e "${CYAN}Bluetooth Security Hardening Toolkit for Linux${NC}"
    echo -e "${WHITE}Version: $SCRIPT_VERSION | Author: Philip S. Wright${NC}"
    echo -e "${YELLOW}Protecting against BlueBorne and related attacks${NC}"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            "debian"|"ubuntu"|"linuxmint"|"pop") echo "debian" ;;
            "rhel"|"centos"|"fedora"|"rocky"|"almalinux") echo "redhat" ;;
            "arch"|"manjaro"|"endeavouros") echo "arch" ;;
            "opensuse"|"opensuse-leap"|"opensuse-tumbleweed") echo "suse" ;;
            "alpine") echo "alpine" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

create_backup() {
    if [[ "$BACKUP" == true ]]; then
        log "INFO" "Creating configuration backup..."
        mkdir -p "$BACKUP_DIR"
        
        # Backup important files
        [[ -f /etc/bluetooth/main.conf ]] && cp /etc/bluetooth/main.conf "$BACKUP_DIR/"
        [[ -d /etc/systemd/system ]] && find /etc/systemd/system -name "*bluetooth*" -exec cp {} "$BACKUP_DIR/" \;
        [[ -d /etc/modprobe.d ]] && find /etc/modprobe.d -name "*bluetooth*" -exec cp {} "$BACKUP_DIR/" \;
        
        log "INFO" "Backup created in $BACKUP_DIR"
    fi
}

# ========================================================================
# System Detection and Package Management
# ========================================================================

install_dependencies() {
    local distro=$(detect_distribution)
    log "INFO" "Installing dependencies for $distro systems..."
    
    case "$distro" in
        "debian")
            apt-get update -qq
            apt-get install -y rfkill systemd bluez-tools 2>/dev/null || true
            ;;
        "redhat")
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y rfkill systemd bluez-tools 2>/dev/null || true
            else
                yum install -y rfkill systemd bluez-tools 2>/dev/null || true
            fi
            ;;
        "arch")
            pacman -S --noconfirm rfkill systemd bluez-utils 2>/dev/null || true
            ;;
        "suse")
            zypper install -y rfkill systemd bluez-tools 2>/dev/null || true
            ;;
        "alpine")
            apk add --no-cache rfkill openrc bluez 2>/dev/null || true
            ;;
        *)
            log "WARN" "Unknown distribution, skipping dependency installation"
            ;;
    esac
}

# ========================================================================
# Bluetooth Service Management
# ========================================================================

disable_bluetooth_services() {
    log "INFO" "Disabling Bluetooth services..."
    
    # Stop all Bluetooth-related services
    local services=(
        "bluetooth"
        "bluetooth.service"
        "bluetooth.target"
        "bluez"
        "bthelper@"
        "hciuart"
    )
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "$service"; then
            log "INFO" "Stopping and disabling $service"
            systemctl stop "$service" 2>/dev/null || true
            systemctl disable "$service" 2>/dev/null || true
            systemctl mask "$service" 2>/dev/null || true
        fi
    done
    
    # Kill any remaining Bluetooth processes
    pkill -f "bluetoothd" 2>/dev/null || true
    pkill -f "bluetooth" 2>/dev/null || true
}

blacklist_bluetooth_modules() {
    log "INFO" "Blacklisting Bluetooth kernel modules..."
    
    local blacklist_file="/etc/modprobe.d/blacklist-bluetooth.conf"
    cat > "$blacklist_file" << 'EOF'
# Bluetooth Hardening - Blacklist all Bluetooth modules
# Generated by Bluetooth Hardening Toolkit

# Core Bluetooth modules
blacklist bluetooth
blacklist btusb
blacklist btrtl
blacklist btbcm
blacklist btintel
blacklist btmtk

# Additional Bluetooth-related modules
blacklist bnep
blacklist rfcomm
blacklist hidp
blacklist hci_uart
blacklist hci_vhci
blacklist hci_bcm
blacklist btsdio

# Bluetooth Audio
blacklist snd_hda_codec_hdmi
blacklist btusb_mtk
blacklist btmrvl
blacklist btmrvl_sdio

# Bluetooth HID
blacklist hid_logitech_dj
blacklist hid_logitech_hidpp
EOF

    log "INFO" "Bluetooth modules blacklisted in $blacklist_file"
    
    # Remove any currently loaded modules
    local modules=(
        "btusb" "bluetooth" "btrtl" "btbcm" "btintel" "btmtk"
        "bnep" "rfcomm" "hidp" "hci_uart" "btsdio"
    )
    
    for module in "${modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            log "INFO" "Removing module: $module"
            rmmod "$module" 2>/dev/null || true
        fi
    done
    
    # Update initramfs
    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -u
    elif command -v dracut >/dev/null 2>&1; then
        dracut -f
    elif command -v mkinitcpio >/dev/null 2>&1; then
        mkinitcpio -P
    fi
}

disable_bluetooth_hardware() {
    log "INFO" "Disabling Bluetooth hardware interfaces..."
    
    # Use rfkill to hard-block Bluetooth
    if command -v rfkill >/dev/null 2>&1; then
        rfkill block bluetooth 2>/dev/null || true
        rfkill block all 2>/dev/null || true
    fi
    
    # Disable via sysfs if available
    for hci_device in /sys/class/bluetooth/hci*; do
        if [[ -d "$hci_device" ]]; then
            echo 0 > "$hci_device/rfkill*/soft" 2>/dev/null || true
            echo 1 > "$hci_device/rfkill*/hard" 2>/dev/null || true
        fi
    done
}

# ========================================================================
# Configuration Hardening
# ========================================================================

harden_bluetooth_config() {
    if [[ "$PROFILE" == "maximum" ]]; then
        log "INFO" "Maximum security profile - complete Bluetooth disable"
        disable_bluetooth_services
        blacklist_bluetooth_modules
        disable_bluetooth_hardware
        return
    fi
    
    log "INFO" "Hardening Bluetooth configuration for profile: $PROFILE"
    
    local bluetooth_conf="/etc/bluetooth/main.conf"
    if [[ -f "$bluetooth_conf" ]]; then
        create_backup
        
        # Create hardened configuration
        cat > "$bluetooth_conf" << 'EOF'
# Hardened Bluetooth Configuration
# Generated by Bluetooth Hardening Toolkit

[General]
# Security settings
Class = 0x000000
DiscoverableTimeout = 0
PairableTimeout = 0
Discoverable = false
Pairable = false

# Disable legacy features
DisablePlugins = autopair,policy
AlwaysPairable = false
RememberPowered = false

# Enhanced security
JustWorksRepairing = never
TemporaryTimeout = 30
EnableAdvMonInterleaveScan = false

# Restrict services
ExperimentalFeatures = 
ControllerMode = dual
MultiProfile = off

# Logging
DebugKeys = false
ControllerMode = bredr

[Policy]
AutoEnable = false
ReconnectAttempts = 0
ReconnectIntervals = 1,2,4,8,16

[GATT]
KeySize = 16
ExchangeMTU = 517
Channels = 1
EOF
        
        log "INFO" "Bluetooth configuration hardened"
    fi
}

# ========================================================================
# Monitoring and Detection
# ========================================================================

setup_monitoring() {
    if [[ "$MONITORING" == true ]]; then
        log "INFO" "Setting up Bluetooth monitoring..."
        
        # Create monitoring script
        cat > "/usr/local/bin/bt-monitor" << 'EOF'
#!/bin/bash
# Bluetooth Security Monitor
# Part of Bluetooth Hardening Toolkit

LOG_FILE="/var/log/bt-security.log"
ALERT_EMAIL="${BT_ALERT_EMAIL:-}"

log_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp [ALERT] $message" >> "$LOG_FILE"
    
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "Bluetooth Security Alert" "$ALERT_EMAIL"
    fi
}

# Monitor for Bluetooth service attempts
while true; do
    # Check if Bluetooth services are trying to start
    if systemctl is-active --quiet bluetooth 2>/dev/null; then
        log_alert "Bluetooth service detected as active - potential security issue"
        systemctl stop bluetooth 2>/dev/null || true
    fi
    
    # Check for loaded Bluetooth modules
    if lsmod | grep -q "^bluetooth\|^btusb"; then
        log_alert "Bluetooth kernel modules detected - potential security bypass"
    fi
    
    # Check for Bluetooth processes
    if pgrep -f "bluetoothd" >/dev/null 2>&1; then
        log_alert "Bluetooth daemon process detected"
        pkill -f "bluetoothd" 2>/dev/null || true
    fi
    
    sleep 60
done
EOF
        
        chmod +x "/usr/local/bin/bt-monitor"
        
        # Create systemd service for monitoring
        cat > "/etc/systemd/system/bt-monitor.service" << 'EOF'
[Unit]
Description=Bluetooth Security Monitor
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bt-monitor
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable bt-monitor.service
        systemctl start bt-monitor.service
        
        log "INFO" "Bluetooth monitoring service installed and started"
    fi
}

# ========================================================================
# Verification and Reporting
# ========================================================================

verify_hardening() {
    log "INFO" "Verifying Bluetooth hardening status..."
    
    local issues=0
    
    # Check service status
    for service in "bluetooth" "bluetooth.service"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "ERROR" "Service $service is still active"
            ((issues++))
        else
            log "INFO" "Service $service is properly disabled"
        fi
    done
    
    # Check for loaded modules
    local bt_modules=$(lsmod | grep -E "^bluetooth|^btusb|^btrtl|^btbcm" | wc -l)
    if [[ $bt_modules -gt 0 ]]; then
        log "ERROR" "$bt_modules Bluetooth modules still loaded"
        ((issues++))
    else
        log "INFO" "No Bluetooth modules loaded"
    fi
    
    # Check rfkill status
    if command -v rfkill >/dev/null 2>&1; then
        local bt_unblocked=$(rfkill list bluetooth | grep -c "Soft blocked: no" || true)
        if [[ $bt_unblocked -gt 0 ]]; then
            log "ERROR" "$bt_unblocked Bluetooth devices not blocked"
            ((issues++))
        else
            log "INFO" "All Bluetooth devices properly blocked"
        fi
    fi
    
    # Check for Bluetooth processes
    if pgrep -f "bluetooth" >/dev/null 2>&1; then
        log "ERROR" "Bluetooth processes still running"
        ((issues++))
    else
        log "INFO" "No Bluetooth processes detected"
    fi
    
    if [[ $issues -eq 0 ]]; then
        log "INFO" "✅ Bluetooth hardening verification PASSED"
        return 0
    else
        log "ERROR" "❌ Bluetooth hardening verification FAILED ($issues issues)"
        return 1
    fi
}

generate_report() {
    local report_file="/tmp/bt-hardening-report-$(date +%Y%m%d-%H%M%S).txt"
    
    log "INFO" "Generating hardening report..."
    
    cat > "$report_file" << EOF
Bluetooth Hardening Report
==========================
Generated: $(date)
System: $(uname -a)
Distribution: $(detect_distribution)
Script Version: $SCRIPT_VERSION
Profile Used: $PROFILE

Service Status:
$(systemctl list-unit-files | grep bluetooth || echo "No Bluetooth services found")

Loaded Modules:
$(lsmod | grep -E "bluetooth|btusb|btrtl|btbcm" || echo "No Bluetooth modules loaded")

RFKill Status:
$(rfkill list bluetooth 2>/dev/null || echo "RFKill not available")

Running Processes:
$(pgrep -af bluetooth || echo "No Bluetooth processes running")

Configuration Files:
$(find /etc -name "*bluetooth*" -type f 2>/dev/null || echo "No Bluetooth configuration files found")

Blacklist Status:
$(cat /etc/modprobe.d/blacklist-bluetooth.conf 2>/dev/null || echo "No blacklist file found")

Verification Result:
EOF

    if verify_hardening; then
        echo "✅ PASSED - System properly hardened against Bluetooth attacks" >> "$report_file"
    else
        echo "❌ FAILED - Issues detected, manual review required" >> "$report_file"
    fi
    
    log "INFO" "Report generated: $report_file"
    
    if [[ "$QUIET" == false ]]; then
        echo ""
        echo -e "${GREEN}📄 Hardening Report:${NC}"
        cat "$report_file"
        echo ""
    fi
}

# ========================================================================
# Command Line Interface
# ========================================================================

show_help() {
    cat << EOF
Bluetooth Hardening Toolkit for Linux v$SCRIPT_VERSION

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --profile PROFILE    Hardening profile (maximum, enterprise, development)
    --disable-all        Complete Bluetooth disable (equivalent to --profile maximum)
    --enable-monitoring  Enable continuous security monitoring
    --dry-run           Show what would be done without making changes
    --no-backup         Skip creating configuration backups
    --quiet             Suppress output except errors
    --verify-only       Only verify current hardening status
    --generate-report   Generate detailed security report
    --help              Show this help message
    --version           Show version information

PROFILES:
    maximum      Complete Bluetooth disable (recommended for servers)
    enterprise   Hardened configuration allowing necessary devices
    development  Minimal hardening for development workstations

EXAMPLES:
    # Complete Bluetooth hardening (recommended)
    sudo $SCRIPT_NAME --disable-all

    # Enterprise hardening with monitoring
    sudo $SCRIPT_NAME --profile enterprise --enable-monitoring

    # Verify current hardening status
    sudo $SCRIPT_NAME --verify-only

    # Generate security report
    sudo $SCRIPT_NAME --generate-report

AUTHOR:
    Philip S. Wright (@pdubbbbbs)
    
LICENSE:
    MIT License - Copyright (c) 2025 Philip S. Wright

For more information: https://github.com/pdubbbbbs/bluetooth-hardening-toolkit
EOF
}

show_version() {
    echo "Bluetooth Hardening Toolkit v$SCRIPT_VERSION"
    echo "Copyright (c) 2025 Philip S. Wright"
    echo "License: MIT"
}

# ========================================================================
# Main Execution
# ========================================================================

main() {
    local verify_only=false
    local generate_report_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --profile)
                PROFILE="$2"
                shift 2
                ;;
            --disable-all)
                PROFILE="maximum"
                shift
                ;;
            --enable-monitoring)
                MONITORING=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --no-backup)
                BACKUP=false
                shift
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            --verify-only)
                verify_only=true
                shift
                ;;
            --generate-report)
                generate_report_only=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                show_version
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate profile
    case "$PROFILE" in
        "maximum"|"enterprise"|"development") ;;
        *) 
            log "ERROR" "Invalid profile: $PROFILE"
            exit 1
            ;;
    esac
    
    # Initialize
    print_banner
    check_root
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    if [[ "$verify_only" == true ]]; then
        verify_hardening
        exit $?
    fi
    
    if [[ "$generate_report_only" == true ]]; then
        generate_report
        exit 0
    fi
    
    # Main hardening process
    log "INFO" "Starting Bluetooth hardening with profile: $PROFILE"
    log "INFO" "System: $(uname -a)"
    log "INFO" "Distribution: $(detect_distribution)"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN MODE - No changes will be made"
        log "INFO" "Would execute hardening profile: $PROFILE"
        log "INFO" "Would install dependencies and harden configuration"
        if [[ "$MONITORING" == true ]]; then
            log "INFO" "Would enable security monitoring"
        fi
        exit 0
    fi
    
    # Execute hardening steps
    install_dependencies
    create_backup
    harden_bluetooth_config
    
    if [[ "$PROFILE" == "maximum" ]]; then
        disable_bluetooth_services
        blacklist_bluetooth_modules  
        disable_bluetooth_hardware
    fi
    
    setup_monitoring
    
    # Verification and reporting
    echo ""
    if verify_hardening; then
        log "INFO" "🎉 Bluetooth hardening completed successfully!"
    else
        log "ERROR" "⚠️  Hardening completed with issues - manual review required"
    fi
    
    generate_report
    
    echo ""
    log "INFO" "Hardening complete. Reboot recommended for full effect."
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "Backup directory: $BACKUP_DIR"
    echo ""
}

# Execute main function with all arguments
main "$@"
