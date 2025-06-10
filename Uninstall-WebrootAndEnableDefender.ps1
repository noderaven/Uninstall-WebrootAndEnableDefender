<#
MIT License

Copyright (c) 2025 noderaven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.SYNOPSIS
    This script automates the uninstallation of Webroot SecureAnywhere, performs a thorough cleanup, and enables Microsoft Defender Antivirus.

.DESCRIPTION
    Designed for maximum compatibility and reliability for unattended execution by combining a staged approach with a forceful, deep-cleaning mechanism.
    1.  Sets the PowerShell Execution Policy to Bypass for the current process.
    2.  Attempts a standard uninstallation using WRSA.exe.
    3.  Performs a two-stage cleanup:
        a. Stage 1: A "gentle" attempt to remove leftover folders.
        b. Stage 2 (Forceful): If Stage 1 fails, it stops services, terminates processes, and performs a deep-level registry and file system purge.
    4.  Conditionally removes WMI entries ONLY if the full cleanup is successful.
    5.  Dynamically uses the correct WMI namespace (SecurityCenter/SecurityCenter2) for the OS.
    6.  Enables and starts Microsoft Defender services.

.EXAMPLE
    .\Uninstall-WebrootAndEnableDefender.ps1
    Run from an elevated PowerShell terminal. A reboot is recommended to finalize cleanup.
#>

# Set the execution policy for the current process to ensure the script can run in restricted environments.
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    # If this fails, there's a bigger issue like a Group Policy override. We'll warn but continue.
    Write-Warning "Failed to set execution policy. The script may be blocked from running. Error: $_"
}

# Set ErrorActionPreference to stop on unhandled errors for the rest of the script.
$ErrorActionPreference = "Stop"

#region Helper Functions

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO","WARNING","ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    Write-Output $logMessage
}

function Stop-WebrootProcesses {
    Write-Log "Stopping Webroot user-mode processes..."
    $processesToStop = @("WRSA", "WRSAUI", "WRCoreService", "WRSkyClient") 
    foreach ($procName in $processesToStop) {
        try {
            if (Get-Process -Name $procName -ErrorAction SilentlyContinue) {
                Write-Log "Stopping process: $procName..."
                Stop-Process -Name $procName -Force -ErrorAction Stop
                Write-Log "Process '$procName' stopped."
            } else {
                Write-Log "Process '$procName' not found."
            }
        } catch {
            Write-Log "Error stopping '$procName': $_" "WARNING"
        }
    }
}

function Remove-WebrootServices {
    Write-Log "Attempting to stop and remove Webroot kernel services..."
    $serviceNames = @("WRSVC", "WRCoreService", "WRSkyClient", "WRkrn", "WRBoot", "wrUrlFlt")
    foreach ($serviceName in $serviceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq 'Running') {
                    Write-Log "Stopping service '$serviceName'..."
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                }
                Write-Log "Deleting service '$serviceName' via sc.exe..."
                sc.exe delete $serviceName
            } else {
                Write-Log "Service '$serviceName' not found."
            }
        } catch {
            Write-Log "Could not stop or delete service '$serviceName'. It may already be gone or protected. Details: $_" "WARNING"
        }
    }
}

function Remove-WebrootRegistry {
    Write-Log "Performing deep-level registry cleanup..."
    $regKeysToRemove = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\WRUNINST",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WRUNINST",
        "HKLM:\SOFTWARE\WOW6432Node\WRData", "HKLM:\SOFTWARE\WOW6432Node\WRCore", "HKLM:\SOFTWARE\WOW6432Node\WRMIDData", "HKLM:\SOFTWARE\WOW6432Node\webroot",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WRUNINST", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WRUNINST",
        "HKLM:\SOFTWARE\WRData", "HKLM:\SOFTWARE\WRMIDData", "HKLM:\SOFTWARE\WRCore", "HKLM:\SOFTWARE\webroot",
        "HKLM:\SYSTEM\ControlSet001\services\WRSVC", "HKLM:\SYSTEM\ControlSet001\services\WRkrn", "HKLM:\SYSTEM\ControlSet001\services\WRBoot",
        "HKLM:\SYSTEM\ControlSet001\services\WRCore", "HKLM:\SYSTEM\ControlSet001\services\WRCoreService", "HKLM:\SYSTEM\ControlSet001\services\wrUrlFlt",
        "HKLM:\SYSTEM\CurrentControlSet\services\WRSVC", "HKLM:\SYSTEM\CurrentControlSet\services\WRkrn", "HKLM:\SYSTEM\CurrentControlSet\services\WRBoot",
        "HKLM:\SYSTEM\CurrentControlSet\services\WRCore", "HKLM:\SYSTEM\CurrentControlSet\services\WRCoreService", "HKLM:\SYSTEM\CurrentControlSet\services\wrUrlFlt"
    )
    
    foreach ($key in $regKeysToRemove) {
        if (Test-Path $key) {
            Write-Log "Removing registry key: $key"
            try { Remove-Item -Path $key -Recurse -Force -ErrorAction Stop }
            catch { Write-Log "Failed to remove registry key '$key'. Details: $_" "WARNING" }
        }
    }
    
    $regStartupPaths = @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    foreach ($path in $regStartupPaths) {
        if (Test-Path $path) {
            try {
                if (Get-ItemProperty -Path $path -Name "WRSVC" -ErrorAction SilentlyContinue) {
                    Write-Log "Removing WRSVC startup item from $path"
                    Remove-ItemProperty -Path $path -Name "WRSVC" -Force -ErrorAction Stop
                }
            } catch { Write-Log "Failed to remove startup item from '$path'. Details: $_" "WARNING" }
        }
    }
}


function Start-ServiceWithCheck {
    param ([string]$ServiceName, [int]$TimeoutSeconds = 30)
    try {
        if (!(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
             Write-Log "Service '$ServiceName' not found. Cannot start it." "WARNING"
             return
        }
        Write-Log "Starting service '$ServiceName'..."
        Start-Service -Name $ServiceName -ErrorAction Stop
        $elapsed = 0
        while ($elapsed -lt $TimeoutSeconds) {
            if ((Get-Service -Name $ServiceName).Status -eq 'Running') {
                Write-Log "Service '$ServiceName' is running."
                return
            }
            Start-Sleep -Seconds 1; $elapsed++
        }
        throw "Service '$ServiceName' failed to start within $TimeoutSeconds seconds."
    } catch {
        Write-Log "Error starting '$ServiceName': $_" "ERROR"
    }
}

function Remove-FolderWithRetry {
    param ([string[]]$Folders, [int]$MaxRetries = 5, [int]$RetryDelaySeconds = 60)
    
    $expandedFolders = $Folders | ForEach-Object { [System.Environment]::ExpandEnvironmentVariables($_) }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Log "Folder deletion attempt $attempt of $MaxRetries..."
        
        foreach ($folder in $expandedFolders) {
            if (Test-Path $folder) {
                try {
                    Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                    Write-Log "Successfully deleted folder: $folder"
                } catch {
                    Write-Log "Error deleting '$folder': $_" "ERROR"
                }
            } elseif ($attempt -eq 1) {
                Write-Log "Folder not found on initial check, skipping: $folder"
            }
        }
        
        $remainingFolders = $expandedFolders | Where-Object { Test-Path $_ }
        if ($remainingFolders.Count -eq 0) {
            Write-Log "All specified Webroot folders have been successfully removed."
            return $true # Success
        }

        Write-Log "The following folders remain: $($remainingFolders -join ', ')" "WARNING"
        if ($attempt -lt $MaxRetries) {
            Write-Log "Retrying in $RetryDelaySeconds seconds..."; Start-Sleep -Seconds $RetryDelaySeconds
        } else {
            Write-Log "Failed to delete all folders after $MaxRetries attempts." "ERROR"
        }
    }
    return $false # Failure
}

#endregion Helper Functions

#region WMI Functions

function Remove-WebrootSecurityCenter {
    param ([string]$OSVersion)
    
    $majorVersion = [int]($OSVersion.Split('.')[0]); $minorVersion = [int]($OSVersion.Split('.')[1])
    $namespace = if ($majorVersion -eq 6 -and $minorVersion -eq 1) { "root\SecurityCenter" } else { "root\SecurityCenter2" }
    Write-Log "Using WMI namespace '$namespace' for this OS version."

    try {
        if (-not (Get-WmiObject -Namespace "root" -Class "__Namespace" | Where-Object {$_.Name -eq $namespace.Split('\')[1]})) {
            Write-Log "WMI namespace '$namespace' does not exist. This is expected on some systems." "INFO"; return
        }
        
        $webrootProducts = Get-WmiObject -Namespace $namespace -Class "AntiVirusProduct" -ErrorAction SilentlyContinue | Where-Object { $_.displayName -like "*Webroot*" }
        if (!$webrootProducts) { Write-Log "No Webroot WMI entries found in '$namespace'."; return }
        
        foreach ($product in $webrootProducts) {
            Write-Log "Removing WMI entry: $($product.displayName)"
            try { $product.Delete(); Write-Log "Successfully removed WMI entry: $($product.displayName)" } 
            catch { Write-Log "Failed to remove WMI entry '$($product.displayName)': $_" "ERROR" }
        }
    } catch { Write-Log "Could not manage WMI entries in '$namespace'. Details: $_" "WARNING" }
}

#endregion WMI Functions

#region Main Script

# --- Initialize ---
$cleanupSuccessful = $false
$OS = Get-WmiObject -Class Win32_OperatingSystem
$OSVersion = $OS.Version
Write-Log "Detected Operating System: $($OS.Caption) (Version: $OSVersion)"

# --- Define Paths ---
$foldersToDelete = @(
    "%ProgramData%\WRData", "%ProgramData%\WRCore", "%ProgramFiles%\Webroot",
    "%ProgramFiles(x86)%\Webroot", "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Webroot SecureAnywhere"
)
$exePaths = @("C:\Program Files (x86)\Webroot\WRSA.exe", "C:\Program Files\Webroot\WRSA.exe")


# --- Stage 0: Standard Uninstall ---
$webrootExePath = $exePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($webrootExePath) {
    Write-Log "Webroot detected at '$webrootExePath', initiating uninstallation..."
    try {
        $process = Start-Process -FilePath $webrootExePath -ArgumentList "-uninstall" -Wait -PassThru -ErrorAction Stop
        Write-Log "Uninstaller exit code: $($process.ExitCode)"
    } catch { Write-Log "Uninstallation command failed to run: $_" "ERROR" }
    
    Write-Log "Waiting up to 5 minutes for uninstaller to complete..."
    $maxWait = 300; $elapsed = 0
    while ((Test-Path $webrootExePath) -and ($elapsed -lt $maxWait)) { Start-Sleep -Seconds 10; $elapsed += 10 }
    if (Test-Path $webrootExePath) {
        Write-Log "Uninstaller did not complete after 5 minutes. Proceeding to forceful cleanup." "WARNING"
    } else { Write-Log "Uninstaller appears to have completed successfully." }
} else { Write-Log "Webroot not detected, proceeding directly to cleanup." }

# --- Stage 1: Gentle Cleanup Attempt ---
Write-Log "--- Starting Stage 1: Gentle Cleanup ---"
$cleanupSuccessful = Remove-FolderWithRetry -Folders $foldersToDelete -MaxRetries 1 -RetryDelaySeconds 0

# --- Stage 2: Forceful Cleanup Attempt ---
if (-not $cleanupSuccessful) {
    Write-Log "--- Gentle cleanup failed. Escalating to Stage 2: Forceful Cleanup ---"
    Stop-WebrootProcesses
    Remove-WebrootServices
    Remove-WebrootRegistry
    Write-Log "Pausing for 10 seconds to allow services and registry changes to apply..."
    Start-Sleep -Seconds 10
    $cleanupSuccessful = Remove-FolderWithRetry -Folders $foldersToDelete
}

# --- Configure MS Defender ---
Write-Log "--- Configuring Microsoft Defender ---"
if (Get-Command -Name "Set-MpPreference" -ErrorAction SilentlyContinue) {
    Write-Log "Modern Defender module found. Using Set-MpPreference..."
    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop } 
    catch { Write-Log "Error using Set-MpPreference. This may resolve after a reboot. Details: $_" "WARNING" }
} else { Write-Log "Modern Defender module not found. Relying on registry edits." }

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
try {
    if (-not (Test-Path $regPath)) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows Defender" -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 0 -Type DWORD -Force -ErrorAction Stop
    $rtRegPath = Join-Path -Path $regPath -ChildPath "Real-Time Protection"
    if (-not (Test-Path $rtRegPath)) { New-Item -Path $regPath -Name "Real-Time Protection" -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $rtRegPath -Name "DisableBehaviorMonitoring" -Value 0 -Type DWORD -Force -ErrorAction Stop
    Set-ItemProperty -Path $rtRegPath -Name "DisableOnAccessProtection" -Value 0 -Type DWORD -Force -ErrorAction Stop
    Set-ItemProperty -Path $rtRegPath -Name "DisableScanOnRealtimeEnable" -Value 0 -Type DWORD -Force -ErrorAction Stop
    Write-Log "Defender registry policies updated successfully."
} catch { Write-Log "Registry update error: $_" "ERROR" }

Start-ServiceWithCheck -ServiceName "WinDefend"
Start-ServiceWithCheck -ServiceName "WdNisSvc"

# --- Conditional WMI Cleanup ---
if ($cleanupSuccessful) {
    Write-Log "--- Cleanup successful. Proceeding with WMI removal. ---"
    Remove-WebrootSecurityCenter -OSVersion $OSVersion
} else {
    Write-Log "--- Cleanup FAILED. Skipping WMI removal to avoid system misconfiguration. ---" "ERROR"
}

Write-Log "Script completed. A reboot is strongly recommended to finalize the removal of all components." "WARNING"

#endregion Main Script
