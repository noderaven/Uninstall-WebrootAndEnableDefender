# Webroot SecureAnywhere Uninstaller & Defender Enabler

This PowerShell script automates the complete uninstallation of Webroot SecureAnywhere, performs a thorough cleanup of leftover files and registry entries, and then ensures Microsoft Defender Antivirus is enabled and running.

## 📄 Description

This script is designed for robust and reliable unattended execution, combining a staged approach with a forceful, deep-cleaning mechanism to remove Webroot and activate Defender. It's particularly useful for system administrators or users needing to completely remove Webroot and switch to the native Windows security solution.

## ✨ Features

* **Execution Policy Bypass:** Temporarily sets the PowerShell execution policy for the current process to allow script execution.

* **Staged Uninstallation:**

  * Attempts a standard uninstallation using `WRSA.exe`.

  * If the standard uninstall is insufficient, it proceeds to a two-stage cleanup.

* **Comprehensive Cleanup:**

  * **Stage 1 (Gentle):** Attempts to remove common leftover Webroot folders.

  * **Stage 2 (Forceful):** If Stage 1 fails, it escalates by stopping Webroot services, terminating processes, and performing a deep-level registry and file system purge.

* **Dynamic WMI Cleanup:** Conditionally removes Webroot entries from WMI (Windows Management Instrumentation) if the cleanup is successful. It dynamically selects the correct WMI namespace (`SecurityCenter` or `SecurityCenter2`) based on the operating system version.

* **Microsoft Defender Activation:**

  * Enables and starts core Microsoft Defender services (`WinDefend`, `WdNisSvc`).

  * Configures Defender through `Set-MpPreference` (if available) and direct registry edits to ensure real-time protection and other features are active.

* **Robust Logging:** Provides clear output messages indicating the script's progress and any encountered issues.

* **Retry Mechanism:** Includes a retry mechanism for folder deletion, making the cleanup more resilient.

## 🚀 Usage

To run this script:

1. **Download:** Save the script (e.g., `Uninstall-WebrootAndEnableDefender.ps1`) to your local machine.

2. **Elevated PowerShell:** Open PowerShell as an **Administrator**.

   * Right-click the PowerShell icon and select "Run as administrator."

3. **Navigate:** Change directory to where you saved the script:
