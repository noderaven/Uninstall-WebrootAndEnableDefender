# Uninstall-WebrootAndEnableDefender

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
