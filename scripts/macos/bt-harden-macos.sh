#!/bin/bash

# ========================================================================
# Bluetooth Hardening Toolkit - macOS Edition
# ========================================================================
# Author: Philip S. Wright (@pdubbbbbs)
# License: MIT
# Description: Comprehensive Bluetooth hardening for macOS systems
# Supports: macOS 10.15+, macOS Big Sur, Monterey, Ventura, Sonoma
# ========================================================================

set -euo pipefail

# Global variables
readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/bt-hardening.log"
readonly BACKUP_DIR="/etc/bt-hardening-backup"
readonly LAUNCHD_PATH="/Library/LaunchDaemons"

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
    
    echo "$timestamp [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

print_banner() {
    if [[ "$QUIET" == false ]]; then
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
        echo -e "${CYAN}Bluetooth Security Hardening Toolkit for macOS${NC}"
        echo -e "${WHITE}Version: $SCRIPT_VERSION | Author: Philip S. Wright${NC}"
        echo -e "${YELLOW}Protecting against BlueBorne and related attacks${NC}"
        echo ""
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos_version() {
    local version=$(sw_vers -productVersion)
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)
    
    log "INFO" "Detected macOS version: $version"
    
    # Check for minimum supported version (10.15+)
    if [[ $major -lt 10 ]] || ([[ $major -eq 10 ]] && [[ $minor -lt 15 ]]); then
        log "ERROR" "This script requires macOS 10.15 (Catalina) or later"
        exit 1
    fi
}

create_backup() {
    if [[ "$BACKUP" == true ]]; then
        log "INFO" "Creating configuration backup..."
        mkdir -p "$BACKUP_DIR"
        
        # Backup important files and settings
        defaults read com.apple.Bluetooth > "$BACKUP_DIR/bluetooth-preferences.plist" 2>/dev/null || true
        cp -f /Library/Preferences/com.apple.Bluetooth.plist "$BACKUP_DIR/" 2>/dev/null || true
        
        # Backup LaunchDaemons
        find "$LAUNCHD_PATH" -name "*bluetooth*" -exec cp {} "$BACKUP_DIR/" \; 2>/dev/null || true
        
        log "INFO" "Backup created in $BACKUP_DIR"
    fi
}

# ========================================================================
# Bluetooth Service Management
# ========================================================================

disable_bluetooth_services() {
    log "INFO" "Disabling Bluetooth services..."
    
    # Stop Bluetooth daemon
    if launchctl list | grep -q "com.apple.bluetoothd"; then
        log "INFO" "Stopping Bluetooth daemon"
        if [[ "$DRY_RUN" == false ]]; then
            launchctl stop com.apple.bluetoothd 2>/dev/null || true
            launchctl unload /System/Library/LaunchDaemons/com.apple.bluetoothd.plist 2>/dev/null || true
        else
            log "INFO" "[DRY RUN] Would stop Bluetooth daemon"
        fi
    fi
    
    # Disable Bluetooth audio services
    local audio_services=(
        "com.apple.bluetoothaudiod"
        "com.apple.bluetoothReporter"
        "com.apple.bluetoothuserd"
    )
    
    for service in "${audio_services[@]}"; do
        if launchctl list | grep -q "$service"; then
            log "INFO" "Disabling service: $service"
            if [[ "$DRY_RUN" == false ]]; then
                launchctl stop "$service" 2>/dev/null || true
                launchctl unload "/System/Library/LaunchAgents/${service}.plist" 2>/dev/null || true
                launchctl unload "/System/Library/LaunchDaemons/${service}.plist" 2>/dev/null || true
            else
                log "INFO" "[DRY RUN] Would disable service: $service"
            fi
        fi
    done
    
    # Kill any remaining Bluetooth processes
    if [[ "$DRY_RUN" == false ]]; then
        pkill -f "bluetoothd" 2>/dev/null || true
        pkill -f "bluetoothaudiod" 2>/dev/null || true
        pkill -f "bluetoothuserd" 2>/dev/null || true
    fi
}

disable_bluetooth_hardware() {
    log "INFO" "Disabling Bluetooth hardware..."
    
    # Disable Bluetooth via blueutil (if available)
    if command -v blueutil >/dev/null 2>&1; then
        log "INFO" "Using blueutil to disable Bluetooth"
        if [[ "$DRY_RUN" == false ]]; then
            blueutil -p 0
        else
            log "INFO" "[DRY RUN] Would run: blueutil -p 0"
        fi
    else
        log "WARN" "blueutil not found, installing..."
        if command -v brew >/dev/null 2>&1; then
            if [[ "$DRY_RUN" == false ]]; then
                brew install blueutil
                blueutil -p 0
            fi
        else
            log "WARN" "Homebrew not found, using alternative methods"
        fi
    fi
    
    # Disable via system preferences
    if [[ "$DRY_RUN" == false ]]; then
        defaults write com.apple.Bluetooth ControllerPowerState -int 0
        defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
    else
        log "INFO" "[DRY RUN] Would set Bluetooth ControllerPowerState to 0"
    fi
}

# ========================================================================
# Configuration Hardening
# ========================================================================

harden_bluetooth_config() {
    if [[ "$PROFILE" == "maximum" ]]; then
        log "INFO" "Maximum security profile - complete Bluetooth disable"
        disable_bluetooth_services
        disable_bluetooth_hardware
        blacklist_bluetooth_kexts
        return
    fi
    
    log "INFO" "Hardening Bluetooth configuration for profile: $PROFILE"
    
    # Apply hardened preferences
    if [[ "$DRY_RUN" == false ]]; then
        # Disable Bluetooth sharing
        defaults write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        
        # Disable discoverable mode
        defaults write com.apple.Bluetooth DiscoverableState -int 0
        
        # Disable automatic connection
        defaults write com.apple.Bluetooth AutoSeekPointingDevice -bool false
        defaults write com.apple.Bluetooth AutoSeekKeyboard -bool false
        
        # Disable Bluetooth wake
        defaults write com.apple.Bluetooth WakeOnWirelessEnabled -bool false
        
        # Enhanced security settings
        defaults write com.apple.Bluetooth RequireAuthentication -bool true
        defaults write com.apple.Bluetooth RequireEncryption -bool true
        
        log "INFO" "Bluetooth preferences hardened"
    else
        log "INFO" "[DRY RUN] Would apply hardened Bluetooth preferences"
    fi
}

blacklist_bluetooth_kexts() {
    log "INFO" "Blacklisting Bluetooth kernel extensions..."
    
    local kext_blacklist="/System/Library/Extensions/IOBluetoothFamily.kext"
    local kext_backup_dir="/System/Library/Extensions/Disabled"
    
    if [[ -d "$kext_blacklist" ]]; then
        if [[ "$DRY_RUN" == false ]]; then
            # Create disabled directory
            mkdir -p "$kext_backup_dir"
            
            # Move Bluetooth kexts to disabled directory
            mv "$kext_blacklist" "$kext_backup_dir/" 2>/dev/null || true
            
            # Clear kernel extension cache
            kextcache -clear-cache 2>/dev/null || true
            
            log "INFO" "Bluetooth kernel extensions blacklisted"
        else
            log "INFO" "[DRY RUN] Would blacklist Bluetooth kernel extensions"
        fi
    fi
}

# ========================================================================
# Profile-specific Hardening
# ========================================================================

apply_enterprise_profile() {
    log "INFO" "Applying Enterprise Bluetooth profile..."
    
    if [[ "$DRY_RUN" == false ]]; then
        # Allow Bluetooth but with strict security
        defaults write com.apple.Bluetooth ControllerPowerState -int 1
        defaults write com.apple.Bluetooth DiscoverableState -int 0
        defaults write com.apple.Bluetooth RequireAuthentication -bool true
        defaults write com.apple.Bluetooth RequireEncryption -bool true
        
        # Disable file sharing via Bluetooth
        defaults write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        
        # Restrict device classes
        defaults write com.apple.Bluetooth RestrictedDeviceClasses -array "Audio/Video" "Peripheral"
        
        log "INFO" "Enterprise Bluetooth profile applied"
    fi
}

apply_development_profile() {
    log "INFO" "Applying Development Bluetooth profile..."
    
    if [[ "$DRY_RUN" == false ]]; then
        # Minimal hardening - just disable discovery
        defaults write com.apple.Bluetooth DiscoverableState -int 0
        defaults write com.apple.Bluetooth RequireAuthentication -bool true
        
        log "INFO" "Development Bluetooth profile applied"
    fi
}

# ========================================================================
# Monitoring and Detection
# ========================================================================

setup_monitoring() {
    if [[ "$MONITORING" == true ]]; then
        log "INFO" "Setting up Bluetooth monitoring..."
        
        # Create monitoring script
        cat > "/usr/local/bin/bt-monitor-macos" << 'EOF'
#!/bin/bash
# Bluetooth Security Monitor for macOS
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

while true; do
    # Check if Bluetooth is enabled
    if blueutil -p 2>/dev/null | grep -q "1"; then
        log_alert "Bluetooth detected as enabled - potential security issue"
        blueutil -p 0 2>/dev/null || true
    fi
    
    # Check for active Bluetooth services
    if launchctl list | grep -q "bluetoothd"; then
        log_alert "Bluetooth daemon detected as active"
        launchctl stop com.apple.bluetoothd 2>/dev/null || true
    fi
    
    # Check for Bluetooth processes
    if pgrep -f "bluetoothd" >/dev/null 2>&1; then
        log_alert "Bluetooth daemon process detected"
        pkill -f "bluetoothd" 2>/dev/null || true
    fi
    
    sleep 60
done
EOF
        
        if [[ "$DRY_RUN" == false ]]; then
            chmod +x "/usr/local/bin/bt-monitor-macos"
            
            # Create LaunchDaemon for monitoring
            cat > "$LAUNCHD_PATH/com.bluetooth-hardening.monitor.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bluetooth-hardening.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/bt-monitor-macos</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/bt-monitor.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/bt-monitor.log</string>
</dict>
</plist>
EOF
            
            # Load the monitoring service
            launchctl load "$LAUNCHD_PATH/com.bluetooth-hardening.monitor.plist"
            
            log "INFO" "Bluetooth monitoring service installed and started"
        else
            log "INFO" "[DRY RUN] Would install Bluetooth monitoring service"
        fi
    fi
}

# ========================================================================
# Verification and Reporting
# ========================================================================

verify_hardening() {
    log "INFO" "Verifying Bluetooth hardening status..."
    
    local issues=0
    
    # Check Bluetooth power state
    if command -v blueutil >/dev/null 2>&1; then
        local power_state=$(blueutil -p 2>/dev/null || echo "unknown")
        if [[ "$power_state" == "1" ]]; then
            log "ERROR" "Bluetooth is still enabled"
            ((issues++))
        else
            log "INFO" "Bluetooth power state is disabled"
        fi
    fi
    
    # Check for active services
    if launchctl list | grep -q "bluetoothd"; then
        log "ERROR" "Bluetooth daemon is still active"
        ((issues++))
    else
        log "INFO" "Bluetooth daemon is properly disabled"
    fi
    
    # Check for running processes
    if pgrep -f "bluetooth" >/dev/null 2>&1; then
        log "ERROR" "Bluetooth processes still running"
        ((issues++))
    else
        log "INFO" "No Bluetooth processes detected"
    fi
    
    # Check preferences
    local controller_state=$(defaults read com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "1")
    if [[ "$controller_state" != "0" && "$PROFILE" == "maximum" ]]; then
        log "ERROR" "Bluetooth controller still enabled in preferences"
        ((issues++))
    else
        log "INFO" "Bluetooth preferences properly configured"
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
Bluetooth Hardening Report for macOS
====================================
Generated: $(date)
System: $(hostname)
macOS Version: $(sw_vers -productVersion)
Script Version: $SCRIPT_VERSION
Profile Used: $PROFILE

Bluetooth Power State:
$(blueutil -p 2>/dev/null | sed 's/^/  /' || echo "  blueutil not available")

Active Services:
$(launchctl list | grep bluetooth | sed 's/^/  /' || echo "  No Bluetooth services found")

Running Processes:
$(pgrep -af bluetooth | sed 's/^/  /' || echo "  No Bluetooth processes running")

System Preferences:
$(defaults read com.apple.Bluetooth 2>/dev/null | head -20 | sed 's/^/  /' || echo "  No Bluetooth preferences found")

Verification Result:
EOF

    if verify_hardening; then
        echo "  ✅ PASSED - System properly hardened against Bluetooth attacks" >> "$report_file"
    else
        echo "  ❌ FAILED - Issues detected, manual review required" >> "$report_file"
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
Bluetooth Hardening Toolkit for macOS v$SCRIPT_VERSION

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

REQUIREMENTS:
    - macOS 10.15 (Catalina) or later
    - Administrator privileges (sudo)
    - Optional: Homebrew for blueutil installation

AUTHOR:
    Philip S. Wright (@pdubbbbbs)
    
LICENSE:
    MIT License - Copyright (c) 2025 Philip S. Wright

For more information: https://github.com/pdubbbbbs/bluetooth-hardening-toolkit
EOF
}

show_version() {
    echo "Bluetooth Hardening Toolkit for macOS v$SCRIPT_VERSION"
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
    check_macos_version
    
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
    log "INFO" "System: $(hostname) ($(sw_vers -productVersion))"
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "DRY RUN MODE - No changes will be made"
        log "INFO" "Would execute hardening profile: $PROFILE"
        if [[ "$MONITORING" == true ]]; then
            log "INFO" "Would enable security monitoring"
        fi
        exit 0
    fi
    
    # Execute hardening steps
    create_backup
    
    case "$PROFILE" in
        "maximum")
            harden_bluetooth_config
            ;;
        "enterprise")
            apply_enterprise_profile
            ;;
        "development")
            apply_development_profile
            ;;
    esac
    
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
    log "INFO" "Hardening complete. System restart recommended for full effect."
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "Backup directory: $BACKUP_DIR"
    echo ""
}

# Execute main function with all arguments
main "$@"
