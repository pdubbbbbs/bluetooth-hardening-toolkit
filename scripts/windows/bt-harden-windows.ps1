# ========================================================================
# Bluetooth Hardening Toolkit - Windows Edition
# ========================================================================
# Author: Philip S. Wright (@pdubbbbbs)  
# License: MIT
# Description: Comprehensive Bluetooth hardening for Windows systems
# Supports: Windows 10, Windows 11, Windows Server 2016+
# Requirements: PowerShell 5.1+ running as Administrator
# ========================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(HelpMessage="Hardening profile (Maximum, Enterprise, Development)")]
    [ValidateSet("Maximum", "Enterprise", "Development")]
    [string]$Profile = "Maximum",
    
    [Parameter(HelpMessage="Disable all Bluetooth functionality")]
    [switch]$DisableAll,
    
    [Parameter(HelpMessage="Enable continuous security monitoring")]
    [switch]$EnableMonitoring,
    
    [Parameter(HelpMessage="Show what would be done without making changes")]
    [switch]$DryRun,
    
    [Parameter(HelpMessage="Skip creating registry backups")]
    [switch]$NoBackup,
    
    [Parameter(HelpMessage="Suppress output except errors")]
    [switch]$Quiet,
    
    [Parameter(HelpMessage="Only verify current hardening status")]
    [switch]$VerifyOnly,
    
    [Parameter(HelpMessage="Generate detailed security report")]
    [switch]$GenerateReport,
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Global Configuration
$Script:Version = "2.0.0"
$Script:LogFile = "$env:SystemRoot\Logs\bt-hardening.log"
$Script:BackupPath = "$env:SystemRoot\bt-hardening-backup"
$Script:ConfigPath = "$env:ProgramData\BluetoothHardening"

# Set profile to Maximum if DisableAll is specified
if ($DisableAll) {
    $Profile = "Maximum"
}

# ========================================================================
# Utility Functions
# ========================================================================

function Write-ColorLog {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    # Write to log file
    try {
        $logDir = Split-Path $Script:LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $Script:LogFile -Value $logEntry -Encoding UTF8
    } catch {
        # Fallback to console only if logging fails
    }
    
    # Console output with colors (unless quiet)
    if (-not $Quiet) {
        switch ($Level) {
            "Info"    { Write-Host "[$Level] $Message" -ForegroundColor Green }
            "Warning" { Write-Host "[$Level] $Message" -ForegroundColor Yellow }
            "Error"   { Write-Host "[$Level] $Message" -ForegroundColor Red }
            "Success" { Write-Host "[$Level] $Message" -ForegroundColor Cyan }
            "Debug"   { Write-Host "[$Level] $Message" -ForegroundColor Blue }
        }
    }
}

function Show-Banner {
    if (-not $Quiet) {
        Write-Host @"

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

"@ -ForegroundColor Magenta

        Write-Host "Bluetooth Security Hardening Toolkit for Windows" -ForegroundColor Cyan
        Write-Host "Version: $($Script:Version) | Author: Philip S. Wright" -ForegroundColor White
        Write-Host "Protecting against BlueBorne and related attacks" -ForegroundColor Yellow
        Write-Host ""
    }
}

function Show-Help {
    Write-Host @"
Bluetooth Hardening Toolkit for Windows v$($Script:Version)

USAGE:
    .\bt-harden-windows.ps1 [PARAMETERS]

PARAMETERS:
    -Profile <String>       Hardening profile (Maximum, Enterprise, Development)
    -DisableAll            Complete Bluetooth disable (equivalent to -Profile Maximum)
    -EnableMonitoring      Enable continuous security monitoring
    -DryRun               Show what would be done without making changes
    -NoBackup             Skip creating registry backups
    -Quiet                Suppress output except errors
    -VerifyOnly           Only verify current hardening status
    -GenerateReport       Generate detailed security report
    -Help                 Show this help message

PROFILES:
    Maximum        Complete Bluetooth disable (recommended for servers)
    Enterprise     Hardened configuration allowing necessary devices
    Development    Minimal hardening for development workstations

EXAMPLES:
    # Complete Bluetooth hardening (recommended)
    .\bt-harden-windows.ps1 -DisableAll

    # Enterprise hardening with monitoring
    .\bt-harden-windows.ps1 -Profile Enterprise -EnableMonitoring

    # Verify current hardening status
    .\bt-harden-windows.ps1 -VerifyOnly

    # Generate security report
    .\bt-harden-windows.ps1 -GenerateReport

REQUIREMENTS:
    - Windows PowerShell 5.1+ or PowerShell Core 6+
    - Administrator privileges
    - Windows 10/11 or Windows Server 2016+

AUTHOR:
    Philip S. Wright (@pdubbbbbs)
    
LICENSE:
    MIT License - Copyright (c) 2025 Philip S. Wright

For more information: https://github.com/pdubbbbbs/bluetooth-hardening-toolkit
"@
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ColorLog -Level "Error" -Message "This script must be run as Administrator"
        throw "Administrator privileges required"
    }
}

function New-RegistryBackup {
    if (-not $NoBackup) {
        Write-ColorLog -Level "Info" -Message "Creating registry backup..."
        
        try {
            if (-not (Test-Path $Script:BackupPath)) {
                New-Item -Path $Script:BackupPath -ItemType Directory -Force | Out-Null
            }
            
            $backupFile = Join-Path $Script:BackupPath "bluetooth-registry-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"
            
            # Export Bluetooth-related registry keys
            $registryPaths = @(
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp",
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum"
            )
            
            foreach ($regPath in $registryPaths) {
                $keyName = ($regPath -split '\\')[-1]
                $exportFile = Join-Path $Script:BackupPath "$keyName-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"
                try {
                    reg export $regPath $exportFile /y 2>$null
                } catch {
                    # Key might not exist, continue
                }
            }
            
            Write-ColorLog -Level "Info" -Message "Registry backup created in $Script:BackupPath"
        } catch {
            Write-ColorLog -Level "Warning" -Message "Failed to create registry backup: $($_.Exception.Message)"
        }
    }
}

# ========================================================================
# Bluetooth Service Management
# ========================================================================

function Disable-BluetoothServices {
    Write-ColorLog -Level "Info" -Message "Disabling Bluetooth services..."
    
    $bluetoothServices = @(
        "BTHPORT",      # Bluetooth Port Driver
        "BthEnum",      # Bluetooth Device Enumeration Service
        "BthLEEnum",    # Bluetooth LE Device Enumeration Service
        "BthMini",      # Bluetooth Mini Port Driver
        "RFCOMM",       # Bluetooth Radio Frequency Communication
        "BthA2dp",      # Bluetooth Audio Device
        "BthHFEnum",    # Bluetooth Hands-Free Audio
        "BthAvctpSvc",  # Bluetooth AVCTP Service
        "BluetoothUserService", # Bluetooth User Service
        "BTAGService",  # Bluetooth Audio Gateway Service
        "btwdins"       # Broadcom Bluetooth
    )
    
    foreach ($serviceName in $bluetoothServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-ColorLog -Level "Info" -Message "Processing service: $serviceName"
                
                if (-not $DryRun) {
                    # Stop the service
                    if ($service.Status -eq 'Running') {
                        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                        Write-ColorLog -Level "Info" -Message "Stopped service: $serviceName"
                    }
                    
                    # Disable the service
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-ColorLog -Level "Info" -Message "Disabled service: $serviceName"
                } else {
                    Write-ColorLog -Level "Info" -Message "[DRY RUN] Would stop and disable service: $serviceName"
                }
            }
        } catch {
            Write-ColorLog -Level "Warning" -Message "Could not process service $serviceName`: $($_.Exception.Message)"
        }
    }
}

function Disable-BluetoothDevices {
    Write-ColorLog -Level "Info" -Message "Disabling Bluetooth devices..."
    
    try {
        $bluetoothDevices = Get-PnpDevice | Where-Object { 
            $_.Class -eq "Bluetooth" -or 
            $_.FriendlyName -like "*Bluetooth*" -or
            $_.InstanceId -like "*BTHENUM*" -or
            $_.InstanceId -like "*USB\VID_*Bluetooth*"
        }
        
        foreach ($device in $bluetoothDevices) {
            try {
                Write-ColorLog -Level "Info" -Message "Processing device: $($device.FriendlyName)"
                
                if (-not $DryRun) {
                    if ($device.Status -eq "OK") {
                        Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                        Write-ColorLog -Level "Info" -Message "Disabled device: $($device.FriendlyName)"
                    }
                } else {
                    Write-ColorLog -Level "Info" -Message "[DRY RUN] Would disable device: $($device.FriendlyName)"
                }
            } catch {
                Write-ColorLog -Level "Warning" -Message "Could not disable device $($device.FriendlyName): $($_.Exception.Message)"
            }
        }
        
        # Also try to disable via Device Manager classes
        $bluetoothClasses = @(
            "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}",  # Bluetooth
            "{00000000-0000-0000-0000-000000000000}"   # Generic Bluetooth
        )
        
        foreach ($classGuid in $bluetoothClasses) {
            try {
                if (-not $DryRun) {
                    # Use DevCon-style approach via registry
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$classGuid"
                    if (Test-Path $regPath) {
                        Set-ItemProperty -Path $regPath -Name "UpperFilters" -Value @() -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                # Continue on error
            }
        }
        
    } catch {
        Write-ColorLog -Level "Warning" -Message "Error disabling Bluetooth devices: $($_.Exception.Message)"
    }
}

function Set-BluetoothRegistryHardening {
    Write-ColorLog -Level "Info" -Message "Applying registry-based Bluetooth hardening..."
    
    $registrySettings = @(
        # Disable Bluetooth services via registry
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT"
            Name = "Start"
            Value = 4
            Type = "DWORD"
            Description = "Disable Bluetooth Port Driver"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\BthEnum"
            Name = "Start" 
            Value = 4
            Type = "DWORD"
            Description = "Disable Bluetooth Device Enumeration"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\BthLEEnum"
            Name = "Start"
            Value = 4
            Type = "DWORD"
            Description = "Disable Bluetooth LE Enumeration"
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RFCOMM"
            Name = "Start"
            Value = 4
            Type = "DWORD"
            Description = "Disable Bluetooth RFCOMM"
        },
        # Disable Bluetooth via Group Policy settings
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "ServicesInitialized"
            Value = 0
            Type = "DWORD"
            Description = "Prevent Bluetooth services initialization"
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "AllowDiscoverableMode"
            Value = 0
            Type = "DWORD"
            Description = "Disable Bluetooth discoverable mode"
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "AllowPrepairing"
            Value = 0
            Type = "DWORD"  
            Description = "Disable Bluetooth pre-pairing"
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "AllowPromptedProximalConnections"
            Value = 0
            Type = "DWORD"
            Description = "Disable prompted proximal connections"
        },
        # Disable Bluetooth advertisement
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ActionCenter\Quick Actions\All\SystemSettings_Device_BluetoothQuickAction"
            Name = "Enabled"
            Value = 0
            Type = "DWORD"
            Description = "Disable Bluetooth quick action"
        }
    )
    
    foreach ($setting in $registrySettings) {
        try {
            Write-ColorLog -Level "Info" -Message "Setting: $($setting.Description)"
            
            if (-not $DryRun) {
                # Create registry path if it doesn't exist
                if (-not (Test-Path $setting.Path)) {
                    New-Item -Path $setting.Path -Force | Out-Null
                }
                
                # Set the registry value
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
                Write-ColorLog -Level "Success" -Message "Applied: $($setting.Description)"
            } else {
                Write-ColorLog -Level "Info" -Message "[DRY RUN] Would set $($setting.Path)\$($setting.Name) = $($setting.Value)"
            }
        } catch {
            Write-ColorLog -Level "Warning" -Message "Failed to apply $($setting.Description): $($_.Exception.Message)"
        }
    }
}

# ========================================================================
# Configuration Hardening by Profile
# ========================================================================

function Set-BluetoothHardening {
    param([string]$HardeningProfile)
    
    New-RegistryBackup
    
    switch ($HardeningProfile) {
        "Maximum" {
            Write-ColorLog -Level "Info" -Message "Applying Maximum security profile - complete Bluetooth disable"
            Disable-BluetoothServices
            Disable-BluetoothDevices
            Set-BluetoothRegistryHardening
            Disable-BluetoothRadio
        }
        "Enterprise" {
            Write-ColorLog -Level "Info" -Message "Applying Enterprise security profile - hardened configuration"
            Set-BluetoothRegistryHardening
            Set-EnterpriseBluetoothPolicy
        }
        "Development" {
            Write-ColorLog -Level "Info" -Message "Applying Development security profile - minimal hardening"
            Set-DevelopmentBluetoothPolicy
        }
    }
}

function Disable-BluetoothRadio {
    Write-ColorLog -Level "Info" -Message "Disabling Bluetooth radio..."
    
    try {
        # Try to disable via WMI
        $bluetoothRadios = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
            $_.Name -like "*Bluetooth*" -and $_.ConfigManagerErrorCode -eq 0 
        }
        
        foreach ($radio in $bluetoothRadios) {
            try {
                if (-not $DryRun) {
                    $radio.Disable()
                    Write-ColorLog -Level "Info" -Message "Disabled Bluetooth radio: $($radio.Name)"
                } else {
                    Write-ColorLog -Level "Info" -Message "[DRY RUN] Would disable radio: $($radio.Name)"
                }
            } catch {
                Write-ColorLog -Level "Warning" -Message "Could not disable radio $($radio.Name): $($_.Exception.Message)"
            }
        }
        
        # Alternative method using netsh (if available)
        try {
            if (-not $DryRun) {
                $null = netsh interface set interface "Bluetooth Network Connection" admin=disabled 2>$null
            }
        } catch {
            # Interface might not exist
        }
        
    } catch {
        Write-ColorLog -Level "Warning" -Message "Error disabling Bluetooth radio: $($_.Exception.Message)"
    }
}

function Set-EnterpriseBluetoothPolicy {
    Write-ColorLog -Level "Info" -Message "Applying Enterprise Bluetooth policies..."
    
    $enterpriseSettings = @(
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "AllowAdvertising"
            Value = 0
            Type = "DWORD"
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"  
            Name = "AllowDiscoverableMode"
            Value = 0
            Type = "DWORD"
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            Name = "AllowPrepairing"
            Value = 0
            Type = "DWORD"
        }
    )
    
    foreach ($setting in $enterpriseSettings) {
        try {
            if (-not $DryRun) {
                if (-not (Test-Path $setting.Path)) {
                    New-Item -Path $setting.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            }
        } catch {
            Write-ColorLog -Level "Warning" -Message "Failed to apply enterprise setting: $($_.Exception.Message)"
        }
    }
}

function Set-DevelopmentBluetoothPolicy {
    Write-ColorLog -Level "Info" -Message "Applying Development Bluetooth policies..."
    
    # Minimal hardening for development - just disable discovery
    try {
        if (-not $DryRun) {
            $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            Set-ItemProperty -Path $path -Name "AllowDiscoverableMode" -Value 0 -Type "DWORD" -Force
        }
    } catch {
        Write-ColorLog -Level "Warning" -Message "Failed to apply development settings: $($_.Exception.Message)"
    }
}

# ========================================================================
# Monitoring and Detection
# ========================================================================

function Set-BluetoothMonitoring {
    if ($EnableMonitoring) {
        Write-ColorLog -Level "Info" -Message "Setting up Bluetooth security monitoring..."
        
        try {
            # Create monitoring script directory
            if (-not (Test-Path $Script:ConfigPath)) {
                New-Item -Path $Script:ConfigPath -ItemType Directory -Force | Out-Null
            }
            
            $monitorScript = @"
# Bluetooth Security Monitor for Windows
# Part of Bluetooth Hardening Toolkit

`$logFile = "$env:SystemRoot\Logs\bt-security-monitor.log"

function Write-SecurityLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "`$timestamp [ALERT] `$Message" | Add-Content -Path `$logFile -Encoding UTF8
    
    # Optional: Send email alert (configure SMTP settings)
    # Send-MailMessage -To "admin@company.com" -Subject "Bluetooth Security Alert" -Body `$Message
}

while (`$true) {
    # Check for active Bluetooth services
    `$activeServices = Get-Service | Where-Object { 
        `$_.Name -like "*Bluetooth*" -or `$_.Name -like "*Bth*" -and `$_.Status -eq "Running" 
    }
    
    foreach (`$service in `$activeServices) {
        Write-SecurityLog "Bluetooth service detected as running: `$(`$service.Name)"
        try {
            Stop-Service -Name `$service.Name -Force
            Set-Service -Name `$service.Name -StartupType Disabled
        } catch {
            Write-SecurityLog "Failed to stop service: `$(`$service.Name)"
        }
    }
    
    # Check for enabled Bluetooth devices
    `$enabledDevices = Get-PnpDevice | Where-Object { 
        (`$_.Class -eq "Bluetooth" -or `$_.FriendlyName -like "*Bluetooth*") -and `$_.Status -eq "OK" 
    }
    
    foreach (`$device in `$enabledDevices) {
        Write-SecurityLog "Bluetooth device detected as enabled: `$(`$device.FriendlyName)"
        try {
            Disable-PnpDevice -InstanceId `$device.InstanceId -Confirm:`$false
        } catch {
            Write-SecurityLog "Failed to disable device: `$(`$device.FriendlyName)"
        }
    }
    
    Start-Sleep -Seconds 60
}
"@
            
            $monitorScriptPath = Join-Path $Script:ConfigPath "BluetoothMonitor.ps1"
            if (-not $DryRun) {
                $monitorScript | Out-File -FilePath $monitorScriptPath -Encoding UTF8 -Force
                
                # Create scheduled task for monitoring
                $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorScriptPath`""
                $taskTrigger = New-ScheduledTaskTrigger -AtStartup
                $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                Register-ScheduledTask -TaskName "BluetoothSecurityMonitor" -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Force | Out-Null
                
                Write-ColorLog -Level "Success" -Message "Bluetooth security monitoring enabled"
            } else {
                Write-ColorLog -Level "Info" -Message "[DRY RUN] Would create monitoring script at: $monitorScriptPath"
            }
            
        } catch {
            Write-ColorLog -Level "Error" -Message "Failed to set up monitoring: $($_.Exception.Message)"
        }
    }
}

# ========================================================================
# Verification and Reporting
# ========================================================================

function Test-BluetoothHardening {
    Write-ColorLog -Level "Info" -Message "Verifying Bluetooth hardening status..."
    
    $issues = 0
    $results = @()
    
    # Check service status
    $bluetoothServices = @("BTHPORT", "BthEnum", "BthLEEnum", "RFCOMM")
    foreach ($serviceName in $bluetoothServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -eq 'Running' -or $service.StartType -ne 'Disabled') {
                $issues++
                $results += "❌ Service $serviceName is not properly disabled (Status: $($service.Status), StartType: $($service.StartType))"
                Write-ColorLog -Level "Error" -Message "Service $serviceName is not properly disabled"
            } else {
                $results += "✅ Service $serviceName is properly disabled"
                Write-ColorLog -Level "Success" -Message "Service $serviceName is properly disabled"
            }
        }
    }
    
    # Check device status
    $bluetoothDevices = Get-PnpDevice | Where-Object { 
        $_.Class -eq "Bluetooth" -or $_.FriendlyName -like "*Bluetooth*" 
    }
    
    foreach ($device in $bluetoothDevices) {
        if ($device.Status -eq "OK") {
            $issues++
            $results += "❌ Bluetooth device enabled: $($device.FriendlyName)"
            Write-ColorLog -Level "Error" -Message "Bluetooth device enabled: $($device.FriendlyName)"
        } else {
            $results += "✅ Bluetooth device disabled: $($device.FriendlyName)"
            Write-ColorLog -Level "Success" -Message "Bluetooth device disabled: $($device.FriendlyName)"
        }
    }
    
    # Check registry settings
    $registryChecks = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT"; Name = "Start"; Expected = 4 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth"; Name = "AllowDiscoverableMode"; Expected = 0 }
    )
    
    foreach ($check in $registryChecks) {
        try {
            $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue
            if ($value -and $value.($check.Name) -eq $check.Expected) {
                $results += "✅ Registry setting correct: $($check.Path)\$($check.Name)"
                Write-ColorLog -Level "Success" -Message "Registry setting correct: $($check.Path)\$($check.Name)"
            } else {
                $issues++
                $results += "❌ Registry setting incorrect: $($check.Path)\$($check.Name)"
                Write-ColorLog -Level "Error" -Message "Registry setting incorrect: $($check.Path)\$($check.Name)"
            }
        } catch {
            $issues++
            $results += "❌ Could not verify registry setting: $($check.Path)\$($check.Name)"
            Write-ColorLog -Level "Error" -Message "Could not verify registry setting: $($check.Path)\$($check.Name)"
        }
    }
    
    # Return results
    $verificationResult = [PSCustomObject]@{
        IssuesFound = $issues
        Passed = ($issues -eq 0)
        Results = $results
    }
    
    if ($verificationResult.Passed) {
        Write-ColorLog -Level "Success" -Message "✅ Bluetooth hardening verification PASSED"
    } else {
        Write-ColorLog -Level "Error" -Message "❌ Bluetooth hardening verification FAILED ($issues issues found)"
    }
    
    return $verificationResult
}

function New-HardeningReport {
    Write-ColorLog -Level "Info" -Message "Generating Bluetooth hardening report..."
    
    $reportPath = "$env:TEMP\bt-hardening-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $verification = Test-BluetoothHardening
    
    $report = @"
Bluetooth Hardening Report for Windows
======================================
Generated: $(Get-Date)
System: $env:COMPUTERNAME
OS Version: $((Get-WmiObject Win32_OperatingSystem).Caption)
PowerShell Version: $($PSVersionTable.PSVersion)
Script Version: $($Script:Version)
Profile Used: $Profile

Service Status:
$(Get-Service | Where-Object { $_.Name -like "*Bluetooth*" -or $_.Name -like "*Bth*" } | Format-Table Name, Status, StartType -AutoSize | Out-String)

Device Status:
$(Get-PnpDevice | Where-Object { $_.Class -eq "Bluetooth" -or $_.FriendlyName -like "*Bluetooth*" } | Format-Table FriendlyName, Status, InstanceId -AutoSize | Out-String)

Registry Settings:
BTHPORT Start: $((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT" -Name "Start" -ErrorAction SilentlyContinue).Start)
Bluetooth Policies: $(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth")

Verification Results:
$($verification.Results -join "`n")

Overall Result: $(if ($verification.Passed) { "✅ PASSED - System properly hardened" } else { "❌ FAILED - $($verification.IssuesFound) issues found" })
"@
    
    $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    Write-ColorLog -Level "Info" -Message "Report generated: $reportPath"
    
    if (-not $Quiet) {
        Write-Host "`n📄 Hardening Report:" -ForegroundColor Green
        Write-Host $report
        Write-Host ""
    }
    
    return $reportPath
}

# ========================================================================
# Main Execution
# ========================================================================

function Main {
    try {
        # Show help if requested
        if ($Help) {
            Show-Help
            return
        }
        
        # Show banner
        Show-Banner
        
        # Check prerequisites
        Test-AdminPrivileges
        
        # Handle special modes
        if ($VerifyOnly) {
            $verification = Test-BluetoothHardening
            exit $(if ($verification.Passed) { 0 } else { 1 })
        }
        
        if ($GenerateReport) {
            New-HardeningReport
            return
        }
        
        # Main hardening process
        Write-ColorLog -Level "Info" -Message "Starting Bluetooth hardening with profile: $Profile"
        Write-ColorLog -Level "Info" -Message "System: $env:COMPUTERNAME ($((Get-WmiObject Win32_OperatingSystem).Caption))"
        
        if ($DryRun) {
            Write-ColorLog -Level "Info" -Message "DRY RUN MODE - No changes will be made"
            Write-ColorLog -Level "Info" -Message "Would execute hardening profile: $Profile"
            if ($EnableMonitoring) {
                Write-ColorLog -Level "Info" -Message "Would enable security monitoring"
            }
            return
        }
        
        # Execute hardening
        Set-BluetoothHardening -HardeningProfile $Profile
        
        if ($EnableMonitoring) {
            Set-BluetoothMonitoring
        }
        
        # Verification
        Write-Host ""
        $verification = Test-BluetoothHardening
        
        if ($verification.Passed) {
            Write-ColorLog -Level "Success" -Message "🎉 Bluetooth hardening completed successfully!"
        } else {
            Write-ColorLog -Level "Warning" -Message "⚠️  Hardening completed with issues - manual review required"
        }
        
        # Generate report
        New-HardeningReport | Out-Null
        
        Write-Host ""
        Write-ColorLog -Level "Info" -Message "Hardening complete. System restart recommended for full effect."
        Write-ColorLog -Level "Info" -Message "Log file: $Script:LogFile"
        Write-ColorLog -Level "Info" -Message "Backup directory: $Script:BackupPath"
        Write-Host ""
        
    } catch {
        Write-ColorLog -Level "Error" -Message "Script execution failed: $($_.Exception.Message)"
        Write-ColorLog -Level "Error" -Message "Stack trace: $($_.ScriptStackTrace)"
        throw
    }
}

# Execute main function
Main
