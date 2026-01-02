# WDS and MDT Deployment Toolkit

This repository contains a fully automated PowerShell script that
installs, configures, and prepares a complete **Windows Deployment
Services (WDS)** and **Microsoft Deployment Toolkit (MDT)** environment
on Windows Server.
It supports both **unattended** and **interactive** execution modes.

---

## 🚀 Features

### **WDS Configuration**

-   Creates a dedicated WDS service account
-   Initializes WDS in standalone mode
-   Configures PXE prompt behavior
-   Sets DHCP/WDS port behavior
-   Creates and prepares the `RemoteInstall` structure

### **Windows ADK + WinPE**

-   Installs Windows ADK (Deployment Tools + USMT; Attention! November 2025 release ADK 26H1 / Nov 2025 build 28000 is NOT USABLE!)
-   Installs WinPE Add-on (Attention! November 2025 release ADK 26H1 / Nov 2025 build 28000 is NOT USABLE!)
-   Creates required x86 WinPE directory

### **MDT Installation & Patch Integration**

-   Installs MDT silently
-   Extracts and applies MDT KB4564442 patch
-   Replaces x86/x64 patched files automatically

### **MDT Deployment Share Setup**

-   Creates DeploymentShare folder
-   Creates admin SMB share
-   Creates Reports, BLKeys, and Logs directories
-   Assigns NTFS + SMB permissions
-   Creates a global MDTProvider PSDrive
-   Enables MDT Monitoring Service

### **Configuration Files**

Automatically generates: - `CustomSettings.ini` (fully populated) -
`Bootstrap.ini` (with credentials included)

### **Boot Image Generation**

-   Updates the DeploymentShare
-   Generates LiteTouchPE_x64.wim
-   Imports boot image into WDS

---

## 📦 Script Modes

### **WDS Role**

Install the WDS Role and Features first:

``` powershell
.\custom_Install_WDS.ps1
```

### **Unattended Mode**

Run with defaults defined in the script:

``` powershell
.\custom_Configure_WDS.ps1
```
<img width="880" height="420" alt="image" src="https://github.com/user-attachments/assets/a4e32562-a34c-41fb-a92c-5f05e9d9c1a7" />
<img width="1596" height="866" alt="image" src="https://github.com/user-attachments/assets/147b02f7-8b71-4b56-9fdf-dbf19b7e0245" />
<img width="1596" height="866" alt="image" src="https://github.com/user-attachments/assets/78ab2634-d572-4490-8041-0ed0422e62ed" />

### **Interactive Mode**

Prompts you for WDS user, password, DeploymentShare path, WSUS settings,
and more:

``` powershell
.\custom_Configure_WDS.ps1 -Interactive
```

---

## 📁 Requirements

-   **Windows Server 2022 / 2025**
-   **PowerShell 5.1** (Powershell 6 and above is NOT supported)
-   **Windows ADK for Windows 11 (Dec 2024 release)**
-   **WinPE Add-on**
-   **MDT 8456**
-   **MDT KB4564442 Patch**

Folder structure example:

    C:\_it\WDS Files 
        ├── ADK     
            └── win11_24h2_adksetup_dez24.exe
            └── win11_24h2_adkwinpesetup_dez24.exe
            ├── Windows PE Environment
                ├── x86 ...
        ├── MDT   
            └── MicrosoftDeploymentToolkit_x64.msi
            └── MicrosoftDeploymentToolkit_x86.msi
            └── MDT_KB4564442.exe
            ├── Bin 
                └── DeploymentTools.xml

---

## 🛠️ What the Script Does

The script automates everything needed for a complete deployment
infrastructure:

1.  WDS setup (PXE, DHCP, permissions)
2.  Install ADK + WinPE
3.  Install + Patch MDT
4.  Create Deployment Share & Log share
5.  Configure permissions
6.  Generate configuration files
7.  Create MDT PSDrive
8.  Update DeploymentShare
9.  Import LiteTouch boot image into WDS

No manual GUI steps required.

---

## 📄 Logging

A detailed installation log is generated automatically:

    C:\_it\install_wds_YYYY-MM-DD_HH-mm-ss.log

---

## ⚠️ Notes

-   Script must be run as **Administrator**
-   Server must be rebooted before running WDS for the first time
-   Ensure ADK + WinPE + MDT files exist in the paths configured

---

## 👤 Author

**Author:** Patrick Scherling  
**Contact:** @Patrick Scherling  

---

> ⚡ *“Automate. Standardize. Simplify.”*  
> Part of Patrick Scherling’s IT automation suite for modern Windows Server infrastructure management.
