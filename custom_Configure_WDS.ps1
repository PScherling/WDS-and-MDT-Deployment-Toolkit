<#
.SYNOPSIS
    Fully automated setup of a complete Windows Deployment Services (WDS) and
    Microsoft Deployment Toolkit (MDT) environment, including Windows ADK, WinPE,
    MDT installation, patching, share creation, permissions, configuration files
    and boot image generation. Supports both unattended and interactive modes.

.DESCRIPTION
    This script installs, configures, and prepares a fully operational 
    deployment environment for Windows using WDS + ADK + WinPE + MDT.

    It performs the following:

    1. **WDS Configuration**
       - Creates WDS service user
       - Initializes WDS in Standalone mode
       - Configures PXE behavior
       - Configures DHCP behavior
       - Prepares RemoteInstall structure

    2. **Windows ADK + WinPE Installation**
       - Installs ADK Deployment Tools and USMT
       - Installs WinPE Addon
       - Creates x86 WinPE platform directory

    3. **MDT Installation & Patch Integration**
       - Installs MDT via MSI
       - Extracts KB4564442 patch
       - Applies x86/x64 patch file replacements

    4. **MDT Folder, Share & Permission Setup**
       - Creates required MDT directories (Logs, Reports, BLKeys, etc.)
       - Creates shares with NTFS + SMB permissions
       - Creates DeploymentShare folder and admin share
       - Creates MDTProvider PSDrive (persistent, global scope)

    5. **MDT Configuration Files**
       - Fully generates CustomSettings.ini
       - Fully generates Bootstrap.ini
       - Enables MDT Monitoring service

    6. **Boot Image Generation**
       - Updates the DeploymentShare
       - Generates LiteTouch PE boot images

    The script can run fully unattended OR interactively when launched with:
        -Interactive

.LINK
    https://learn.microsoft.com/en-us/powershell/module/wds/?view=windowsserver2025-ps
	https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wdsutil
	https://learn.microsoft.com/de-de/windows-hardware/get-started/adk-offline-install
	https://learn.microsoft.com/de-de/previous-versions/windows/it-pro/windows-8.1-and-8/dn621910(v=win.10)
	https://learn.microsoft.com/en-us/intune/configmgr/mdt/
	https://learn.microsoft.com/en-us/intune/configmgr/mdt/mdt-windows-powershell-cmdlets
	https://learn.microsoft.com/en-us/intune/configmgr/mdt/use-the-mdt#InstallingaNewInstanceofMDT
	https://www.deploymentresearch.com/windows-11-deployment-using-mdt-8456-with-windows-adk-24h2-build-26100/
	https://devblogs.microsoft.com/scripting/learn-how-to-use-powershell-to-automate-mdt-deployment/
	https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare?view=windowsserver2025-ps
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.5
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/new-localuser?view=powershell-5.1
	https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.4
	https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
	https://github.com/PScherling
	
.NOTES
          FileName: custom_Configure_WDS.ps1
          Solution: Configures MS WDS Roles and Features
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2025-11-17
          Modified: 2026-01-02

          Version - 0.0.1 - () - Finalized functional version 1.
		  Version - 0.0.2 - () - Check if install files need to be downloaded
		  Version - 0.0.3 - () - Adding Progress Information
		  Version - 0.0.4 - (2026-01-02) - Forcing Windows ADK release december 2024 because november 2025 release is broken by microsoft
          

          TODO:
		  - If ADK x86 sourc folder is present, check if we need to unzip something
		  - Copy OEM Background to MDT installdir

.PARAMETER Interactive
    Enables prompts for confirmations.

.EXAMPLE
	Unattended mode:
		PS> .\custom_Configure_WDS.ps1

	Interactive mode:
		PS> .\custom_Configure_WDS.ps1 -Interactive

#>

param(
    [switch]$Interactive
)

# If we are not using PowerShell 5.x
<#
if ($PSVersionTable.PSVersion.Major -ge 6) {
    Write-Host "ERROR: This script requires Windows PowerShell 5.1" -ForegroundColor Red
    Write-Host "Please run it using: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (e.g. 'powershell.exe -File .\custom_Configure_WDS.ps1')" -ForegroundColor Yellow
    exit 1
}
#>
if ($PSVersionTable.PSVersion.Major -ge 6) {
	Write-Host "This script requires Windows PowerShell 5.1" -ForegroundColor Red
    Write-Host "Restarting script in Windows PowerShell 5.1" -ForegroundColor Cyan
    $ps51 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    Start-Process $ps51 -ArgumentList "-ExecutionPolicy Bypass -Windowstyle maximized -File `"$PSCommandPath`""
    exit
}

# =====================================================================
# GLOBAL CONFIG OBJECT
# =====================================================================

$Config = [PSCustomObject]@{
    Feature         = "WDS"
	Version         = "0.0.4"
    CompName        = $env:COMPUTERNAME

	WDSUser         = "wds.usr"
    WDSPassword     = "Pa55w0rd2025!"
	WDSMode         = "Standalone"
    RemInstall      = "D:\RemoteInstall"
	AnswerClients   = "All" # All; Known; None
	PxepromptKnown  = "NoPrompt" # OptIn; Noprompt; OptOut
	PxepromptNew    = "NoPrompt" # OptIn; Noprompt; OptOut
	UseDhcpPorts    = "No" # Yes; No
	#DhcpOption60    = "No" # Yes; No

	SrcDirs         = @("C:\_it", "C:\_it\WDS Files", "C:\_it\WDS Files\ADK", "C:\_it\WDS Files\MDT")
	LogDir          = "C:\_it"
    SourceRoot      = "C:\_it\WDS Files"
    ADKSetup        = "C:\_it\WDS Files\ADK\adksetup.exe"
    WinPESetup      = "C:\_it\WDS Files\ADK\adkwinpesetup.exe"
	ADKInstPath     = "D:\WindowsKits\ADK"

    ADKx86Dst       = "D:\WindowsKits\ADK\Assessment and Deployment Kit\Windows Preinstallation Environment\x86"

    MDTSetup        = "C:\_it\WDS Files\MDT\MicrosoftDeploymentToolkit_x64.msi"
    MDTPatch        = "C:\_it\WDS Files\MDT\MDT_KB4564442.exe"
    MDTExtractDir   = "C:\_it\WDS Files\MDT\MDT_KB4564442"
    MDTModule       = "$env:ProgramFiles\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"

    DeploymentShare = "D:\DeploymentShare"
	DSName          = "DS001"
    DeploymentShareName = "DeploymentShare$"
    DeploymentShareDesc = "MDT Deployment Share"
	MDTLogShare     = "D:\Logs"
	MDTLogName      = "Logs$"
	MDTLogDesc      = "MDT Log Share"
    MDTDirs         = @("D:\Reports", "D:\BLKeys")
	BootImagePath   = "D:\DeploymentShare\Boot"
	ImageFile       = "LiteTouchPE_x64.wim"
	ImageName       = "Lite Touch Windows PE (x64)"
	ImageDesc       = "Lite Touch Windows PE (x64)"

	UseWSUS         = "No" # No; Yes
	WSUSServer      = ""

	SMSTSOrgName    = "Company"
	SMSTSPackageName = "Windows Deployment System"

	MDTMonitor      = $env:COMPUTERNAME
	MDTMonitorEvent = 9800
	MDTMonitorData  = 9801

	# Download URLs
	MdtURL = "https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi"
	AdkURL = "https://go.microsoft.com/fwlink/?linkid=2289980" # ADK 10.1.26100.2454 (December 2024)
	AdkPeURL = "https://go.microsoft.com/fwlink/?linkid=2289981" # ADK 10.1.26100.2454 (December 2024)
	MdtPatchURL = "https://download.microsoft.com/download/3/0/6/306AC1B2-59BE-43B8-8C65-E141EF287A5E/KB4564442/MDT_KB4564442.exe"

	Error = 0
}

function Confirm-RootDir {
	foreach($dir in $($Config.SrcDirs)){
		If (-not (Test-Path "$($dir)")) { 
			Write-Host "INFO: Creating Directory '$($dir)'."
			try{
				New-Item -Path "$($dir)" -ItemType Directory | Out-Null
			}
			catch{
				Write-Host -ForegroundColor Red "ERROR: Directory '$($dir)' could not be created. $_"
			}
		}
	}
}

# Downloading File
function Start-DownloadInstallerFile {
    param (
        [string]$Url,
        [string]$DestinationPath
    )
    try {
        Start-BitsTransfer -Source $Url -Destination $DestinationPath -ErrorAction Stop
        Write-Log "Download completed using BITS: $DestinationPath"
    } catch {
        Write-Log "BITS download failed: $_" "WARN"

        # Fallback: Use Invoke-WebRequest
        try {
            Write-Host "URL: $Url"
            Invoke-WebRequest -Uri $Url -OutFile $DestinationPath
            Write-Log "Fallback download completed: $DestinationPath"
        } catch {
            Write-Log "Fallback download failed: $_" "ERROR"
            #continue
        }
    }
}

function Initialize-InteractiveConfig {
    Write-Host "`n=== INTERACTIVE CONFIGURATION MODE ===" -ForegroundColor Cyan

    # WDS Service User
    $Config.WDSUser = Read-Host "Enter WDS service account username (default: wds.usr)"
    if ([string]::IsNullOrWhiteSpace($Config.WDSUser)) { $Config.WDSUser = "wds.usr" }

    # WDS Password
    $Config.WDSPassword = Read-Host "Enter password for WDS user '$($Config.WDSUser)'" -AsSecureString
	if ([string]::IsNullOrWhiteSpace($Config.WDSPassword)) { $Config.WDSPassword = "Pa55w0rd2025!" }

    # Deployment Share
    $ds = Read-Host "Enter MDT Deployment Share path (default: D:\DeploymentShare)"
    if (-not $ds) { $ds = "D:\DeploymentShare" }
    $Config.DeploymentShare = $ds

    # RemoteInstall Folder
    $ri = Read-Host "Enter RemoteInstall WDS path (default: D:\RemoteInstall)"
    if (-not $ri) { $ri = "D:\RemoteInstall" }
    $Config.RemInstall = $ri

    # Logs directory
    $logd = Read-Host "Enter local log directory (default: C:\_it)"
    if (-not $logd) { $logd = "C:\_it" }
    $Config.LogDir = $logd

    # Deployment Share admin share name
    $shareName = Read-Host "Enter deployment share (admin) share name (default: DeploymentShare$)"
    if (-not $shareName) { $shareName = "DeploymentShare$" }
    $Config.DeploymentShareName = $shareName

    # Optional: ADK install path override
    $adkOverride = Read-Host "Enter ADK install directory (leave blank to use default: D:\WindowsKits\ADK)"
    if ($adkOverride) { 
        $Config.ADKInstallPath = $adkOverride 
		$Config.ADKx86Dst = "$($adkOverride)\Assessment and Deployment Kit\Windows Preinstallation Environment\x86"
    } else {
        $Config.ADKInstallPath = "D:\WindowsKits\ADK"
    }

	# Optional: WSUS
	$UseWSUS = Read-Host "Do you want to use a WSUS server (default: No)? (y/n)"
	if ($UseWSUS -eq "y")
	{
		$Config.UseWSUS = "Yes"
		$Config.WSUSServer = Read-Host "Enter the name of the WSUS server to use (eg. WSUSSRV1)"
		if ([string]::IsNullOrWhiteSpace($Config.WSUSServer)) { $Config.WSUSServer = "" }
	}

	# Optional: Personalization
	# Org Name
    $orgName = Read-Host "Enter an organization name (default: Company)"
    if (-not $orgName) { $orgName = "Company" }
    $Config.SMSTSOrgName = $orgName

	# Package Name
    $pkgName = Read-Host "Enter an package name (default: Windows Deployment System)"
    if (-not $pkgName) { $pkgName = "Windows Deployment System" }
    $Config.SMSTSPackageName = $pkgName

    Write-Host "`n=== Interactive config complete ===`n" -ForegroundColor Green
}

# =====================================================================
# LOGGING
# =====================================================================

$script:LogFile = Join-Path $Config.LogDir ("install_wds_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HH-mm-ss"))

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR")] 
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    $line | Out-File -FilePath $script:LogFile -Append

    switch ($Level) {
        "INFO"  { Write-Host $line }
		"OK"    { Write-Host $line -ForegroundColor Green }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
    }
}

function Confirm-Step {
    param([string]$Message)
    if (-not $Interactive) { return $true }
    $response = Read-Host "$Message (Y/N)"
    return ($response -match "^[Yy]$")
}

# =====================================================================
# UTILITY FUNCTIONS
# =====================================================================

function Invoke-Safe {
    param(
        [ScriptBlock]$Code,
        [string]$Action
    )

	# Reset error state per action
    $Config.Error = 0

    try {
        & $Code
    }
    catch {
		$Config.Error = 1
		Write-Log "$Action failed" "ERROR"
		throw
    }
	finally{
		if($Config.Error -eq 0){	
			Write-Log "$Action succeed" "OK"
		}
	}
}

# =====================================================================
# WDS FUNCTIONS
# =====================================================================
function Confirm-InstallFiles {
	Write-Log "Checking if we need to download required installation files."
	
	# Checking ADK
	Write-Log "Checking Windows ADK."
	If (-not (Test-Path $($Config.ADKSetup))) { 
		Write-Log "ADK Setup not found. We need to download it." "WARN"
		
		# Start Download
		Invoke-Safe {
			Start-DownloadInstallerFile -Url $($Config.AdkURL) -DestinationPath $($Config.ADKSetup)
		} "Download file"
		
	}
	else{
		Write-Log "Setup file found. Nothing to download."
	}

	# Checking ADK WinPE
	Write-Log "Checking Windows PE ADK."
	If (-not (Test-Path $($Config.WinPESetup))) { 
		Write-Log "WinPE ADK Setup not found. We need to download it." "WARN"
		
		# Start Download
		Invoke-Safe {
			Start-DownloadInstallerFile -Url $($Config.AdkPeURL) -DestinationPath $($Config.WinPESetup)
		} "Download file"
		
	}
	else{
		Write-Log "Setup file found. Nothing to download."
	}

	# Checking MDT Setup
	Write-Log "Checking MDT."
	If (-not (Test-Path $($Config.MDTSetup))) { 
		Write-Log "MDT Setup not found. We need to download it." "WARN"
		
		# Start Download
		Invoke-Safe {
			Start-DownloadInstallerFile -Url $($Config.MdtURL) -DestinationPath $($Config.MDTSetup)
		} "Download file"
		
	}
	else{
		Write-Log "Setup file found. Nothing to download."
	}

	# Checking MDT Patch
	Write-Log "Checking MDT Patch."
	If (-not (Test-Path $($Config.MDTPatch))) { 
		Write-Log "MDT Patch not found. We need to download it." "WARN"
		
		# Start Download
		Invoke-Safe {
			Start-DownloadInstallerFile -Url $($Config.MdtPatchURL) -DestinationPath $($Config.MDTPatch)
		} "Download file"
		
	}
	else{
		Write-Log "Setup file found. Nothing to download."
	}
}

function New-WDSUser {
	
    Write-Log "Creating WDS service user '$($Config.WDSUser)'"
	$securePW = ConvertTo-SecureString $Config.WDSPassword -AsPlainText -Force

	Invoke-Safe {
		New-LocalUser -Name $Config.WDSUser `
			-Password $securePW `
			-AccountNeverExpires `
			-UserMayNotChangePassword `
			-FullName "Windows Deployment User" `
			-Description "Windows Deployment User" | Out-Null
	} "Create local WDS user"
	
}

function Initialize-WDSMode {
	
    Write-Log "Initializing WDS Mode."
	Invoke-Safe {
		wdsutil /Initialize-Server /Server:localhost /$($Config.WDSMode) /reminst:"$($Config.RemInstall)" 1>$null 2>&1
	} "WDS initialization"
	
}

function Start-ConfigureWDS {
	

    Write-Log "Configuring WDS"
	Invoke-Safe { wdsutil /Set-Server /AnswerClients:$($Config.AnswerClients) 1>$null 2>&1 } "Set WDS to answer ALL clients"
	Invoke-Safe { wdsutil /Set-Server /PxePromptPolicy /Known:$($Config.PxePromptKnown) 1>$null 2>&1 } "Set PXE Prompt for Known Clients to NoPrompt"
	Invoke-Safe { wdsutil /Set-Server /PxePromptPolicy /New:$($Config.PxePromptNew) 1>$null 2>&1 } "Set PXE Prompt for Unknown Clients to NoPrompt"
	Invoke-Safe { wdsutil /Set-Server /UseDhcpPorts:$($Config.UseDhcpPorts) 1>$null 2>&1 } "Disable WDS DHCP port listening"
	#Invoke-Safe { wdsutil /Set-Server /DhcpOption60:$($Config.DhcpOption60) 1>$null 2>&1 } "Disable WDS DHCP Option listening"
	
}

# =====================================================================
# ADK FUNCTIONS
# =====================================================================

function Install-ADK {
	
    if (-not (Confirm-Step "Install Windows ADK?")) { return }

    Write-Log "Installing Windows ADK"
	Invoke-Safe {
		Start-Process -FilePath "$($Config.ADKSetup)" `
			-ArgumentList "/quiet /norestart /ceip off /installpath $($Config.ADKInstPath) /features OptionId.DeploymentTools OptionId.UserStateMigrationTool" `
			-Wait -NoNewWindow
	} "Install ADK"
	
}

function Install-WinPE {
	
    if (-not (Confirm-Step "Install WinPE?")) { return }

    Write-Log "Installing WinPE Addon"
	Invoke-Safe {
		Start-Process -FilePath "$($Config.WinPESetup)" `
			-ArgumentList "/quiet /norestart /ceip off /installpath $($Config.ADKInstPath) /features OptionId.WindowsPreinstallationEnvironment" `
			-Wait -NoNewWindow
	} "Install WinPE"
	
}

function Import-ADKx86 {

	Write-Log "Create ADK WinPE x86 directory"
	try{
		Invoke-Safe {
			if (-not (Test-Path "$($Config.ADKx86Dst)")) {
				New-Item -ItemType Directory -Path "$($Config.ADKx86Dst)" -Force | Out-Null
			}
		} "Create ADK x86 destination directory"
	}
	catch{
		Write-Log "Create ADK WinPE x86 directory failed: $_" "ERROR"
	}
	
}

# =====================================================================
# MDT FUNCTIONS
# =====================================================================

function Install-MDT {
	
    if (-not (Confirm-Step "Install MDT?")) { return }

    Write-Log "Installing MDT"
	Invoke-Safe {
		Start-Process msiexec.exe -Wait -WorkingDirectory $PSScriptRoot -ArgumentList "/i `"$($Config.MDTSetup)`" /qn /norestart"
	} "Install MDT"
	
}

function Install-MDTPatch {
	
    Write-Log "Extracting MDT patch"
	Invoke-Safe {
		Start-Process -FilePath "$($Config.MDTPatch)" -ArgumentList "-q", "-extract:`"$($Config.MDTExtractDir)`"" -Wait
	} "Extract MDT patch"
	

    Write-Log "Copying Patch Files"
	Invoke-Safe {
		Copy-Item "$($Config.MDTExtractDir)\x64\*" "$env:ProgramFiles\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x64" -Force
		Copy-Item "$($Config.MDTExtractDir)\x86\*" "$env:ProgramFiles\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x86" -Force
	} "Copy MDT patch files"
	
}

function New-MDTFolders {
    Write-Log "Creating MDT directories"
	
    foreach ($dir in $Config.MDTDirs) {
		Invoke-Safe {
			if (-not (Test-Path "$($dir)")) {
				New-Item -ItemType Directory -Path "$($dir)" -Force | Out-Null
			}
		} "Create directory $($dir)"
		
    }
}

function Set-MDTSharePermissions {
    Write-Log "Setting NTFS and Share permissions"

    foreach ($dir in $Config.MDTDirs) {
		
        # Share creation
        $shareName = Split-Path $dir -Leaf
		Invoke-Safe {
			New-SmbShare -Name "$($shareName)" -Path "$($dir)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
		} "Create share $($shareName)"
		

        # NTFS Permissions
		Invoke-Safe {
			icacls $dir /grant '"Users":(OI)(CI)(RX)' | Out-Null
			icacls $dir /grant '"Administrators":(OI)(CI)(F)' | Out-Null
			icacls $dir /grant '"SYSTEM":(OI)(CI)(F)' | Out-Null
			icacls $dir /grant `"$($Config.CompName)\$($Config.WDSUser)`"':(OI)(CI)(M)' | Out-Null
		} "Set NTFS permissions for $($dir)"
		
    }
}

function New-DeploymentShare {
    Write-Log "Creating MDT Deployment Share"
	
    # Folder
	Invoke-Safe {
		if (-not (Test-Path $Config.DeploymentShare)) {
			New-Item -ItemType Directory -Path "$($Config.DeploymentShare)" -Force | Out-Null
		}
	} "Create DeploymentShare folder"
	

    # Share
	Invoke-Safe {
		New-SmbShare -Name "$($Config.DeploymentShareName)" -Path "$($Config.DeploymentShare)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
	} "Create MDT share"
	

    # MDT PSDrive (will only work if MDT provider is functioning)
	Import-Module $Config.MDTModule -ErrorAction Stop

	Invoke-Safe {
		New-PSDrive -Name "$($Config.DSName)" -PSProvider "MDTProvider" -Root "$($Config.DeploymentShare)" -Description "$($Config.DeploymentShareDesc)" -Scope Global | Add-MDTPersistentDrive | Out-Null
	} "Create MDT PSDrive"
	
}

function New-LogShare {
    Write-Log "Creating MDT Log Share"
	
    # Folder
	Invoke-Safe {
		if (-not (Test-Path $Config.MDTLogShare)) {
			New-Item -ItemType Directory -Path "$($Config.MDTLogShare)" -Force | Out-Null
		}
	} "Create Log Share folder"
	
    # Share
	Invoke-Safe {
		New-SmbShare -Name "$($Config.MDTLogName)" -Path "$($Config.MDTLogShare)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
	} "Create MDT Log share"

	

}

<#
function Set-MDTMonitoring {
	Write-Log "Configure Event Monitoring Service"
	# Enable Event Monitoring
	
	try{
		Invoke-Safe {
			Set-MDTMonitorData -Server "$($Config.MDTMonitor)" -EventPort $($Config.MDTMonitorEvent) -DataPort $($Config.MDTMonitorData) | Out-Null
		} "Set event monitoring configuration"
	} 
	catch{
		
	}
	finally{
		if($ok){
			Write-Log "Set event monitoring configuration succeed" "OK"
		}
		else{
			Write-Log "Set event monitoring configuration failed: $_" "ERROR"
		}
	}
}
#>
function Enable-MDTMonitoring {
	Write-Log "Enable Event Monitoring Service"
	# Enable Event Monitoring

	Invoke-Safe {
		Enable-MDTMonitorService -EventPort $($Config.MDTMonitorEvent) -DataPort $($Config.MDTMonitorData) | Out-Null
	} "Enable Event Monitoring Service"
	
}

function Set-CustomSettingsIni {
	## MDT configuration
    ## Build share CustomSettings.ini

	Write-Log "Build MDT Deployment Share 'CustomSettings.ini'"

	Write-Log "Backing up original 'CustomSettings.ini'"
	Invoke-Safe {
		Rename-Item -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -NewName "CustomSettings_Orig.ini"
	} "Backup 'CustomSettings.ini' file"

	Write-Log "Creating new 'CustomSettings.ini'"
	Invoke-Safe {
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "[Settings]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "Priority=Model,Make,Default"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "Properties=Make,SerialNumber,MyCustomProperty"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "[Default]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "OSInstall=Y"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipCapture=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipProductKey=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipComputerBackup=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipBitLocker=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipPackageDisplay=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipComputerName=NO"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value 'OSDComputerName=#left("%Make%",2)#-#right("%SerialNumber%",6)#'
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipDomainMembership=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "JoinWorkgroup=WORKGROUP"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipUserData=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "UserDataLocation=NONE"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "ComputerBackupLocation=NONE"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipDeploymentType=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "DeploymentType=NEWCOMPUTER"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipRoles=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "HIDESHELL=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Locale and Time"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipLocaleSelection=NO"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "UserLocale=de-DE"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "UILanguage=en-US"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "KeyboardLocale=de-DE"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "KeyboardLocalePE=0407:00000407"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipTimeZone=NO"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "TimeZoneName=W. Europe Standard Time"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Administrator Password"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipAdminPassword=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "AdminPassword=Wa144i12!"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipAdminAccounts=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Ready to begin"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipSummary=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SkipFinalSummary=NO"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Personalization"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "_SMSTSOrgName=$($Config.SMSTSPackageName)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "_SMSTSPackageName=$($Config.SMSTSPackageName)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Monitoring"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "EventService=http://$($Config.MDTMonitor):$($Config.MDTMonitorEvent)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";WSUS"
		if($Config.UseWSUS -eq "Yes") {
			Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "WSUSServer=http://$($Config.WSUSServer):8530"
		}
		else {
			Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";WSUSServer=http://:8530"
		}
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Logging"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "SLShare=\\\\$($Config.CompName)\$($Config.MDTLogName)\\#day(date) & '-' & month(date) & '-' & year(date) & '_' & hour(now) & '-' & minute(now)#" #'SLShare=\\`"'$($Config.CompName)`"'\Logs$\#day(date) & "-" & month(date) & "-" & year(date) & "_" & hour(now) & "-" & minute(now)#'
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Selection Profiles"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- VIRTUELL ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Microsoft HyperV - VM"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "[Virtual Machine]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";WizardSelectionProfile="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Applications001="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";VMware 7 - VM"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "[VMware7,1]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";WizardSelectionProfile="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Applications001="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";VMware 8 - VM"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "[VMware20,1]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";WizardSelectionProfile="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";Applications001="
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- SERVER ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- HP ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- Dell ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- Lenovo ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- CLIENT ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- HP ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- Dell ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ";--------------------------------------------------------- Lenovo ---------------------------------------------------------"
		Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value ""
	} "Generating 'CustomSettings.ini' file"
	
}

function Set-BootstrapIni {
	## MDT configuration
    ## Build share Bootstrap.ini

	Write-Log "Build MDT Deployment Share 'Bootstrap.ini'"

	Write-Log "Backing up original 'Bootstrap.ini'"
	Invoke-Safe {
		Rename-Item -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -NewName "Bootstrap_Orig.ini"
	} "Backup 'Bootstrap.ini' file"

	Write-Log "Creating new 'Bootstrap.ini'"
	Invoke-Safe {
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "[Settings]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "Priority=Default"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value ""
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "[Default]"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "DeployRoot=\\$($Config.CompName)\$($Config.DeploymentShareName)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "SkipBDDWelcome=YES"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "KeyboardLocale=de-DE"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "KeyboardLocalePE=0407:00000407"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "UserDomain=$($Config.CompName)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "UserID=$($Config.WDSUser)"
		Add-Content -Path "$($Config.DeploymentShare)\Control\Bootstrap.ini" -Value "UserPassword=$($Config.WDSPassword)"
	} "Generating 'Bootstrap.ini' file"
	
}

function Update-DeploymentShare {
	Write-Log "Updating Deployment Share and generating boot media"
	
	Invoke-Safe {
		Update-MDTDeploymentShare -Path "$($Config.DSName):" -Force | Out-Null
	} "Update DeploymentShare"
	
}

function Update-WDSBootImage {
	Write-Log "Updating WDS Boot Image"
	
	Invoke-Safe {
		Import-WdsBootImage -Path "$($Config.BootImagePath)\$($Config.ImageFile)" -NewImageName "$($Config.ImageName)" -NewFileName "$($Config.ImageFile)" -NewDescription "$($Config.ImageDesc)" -SkipVerify | Out-Null
	} "Update DeploymentShare"
	
}

# =====================================================================
# EXECUTION PIPELINE
# =====================================================================
###
### Showing the menu
###
Clear-Host

Write-Host -ForegroundColor Cyan "
    +----+ +----+     
    |####| |####|     
    |####| |####|       WW   WW II NN   NN DDDDD   OOOOO  WW   WW  SSSS
    +----+ +----+       WW   WW II NNN  NN DD  DD OO   OO WW   WW SS
    +----+ +----+       WW W WW II NN N NN DD  DD OO   OO WW W WW  SSS
    |####| |####|       WWWWWWW II NN  NNN DD  DD OO   OO WWWWWWW    SS
    |####| |####|       WW   WW II NN   NN DDDDD   OOOO0  WW   WW SSSS
    +----+ +----+       
"
Write-Host "-----------------------------------------------------------------------------------"
Write-Host "              Configuration Summary"
Write-Host "-----------------------------------------------------------------------------------"
Write-Host "
    + Version                  $($Config.Version)
    + Hostname                 $($Config.CompName)
    + Source Structure         $($Config.SrcDirs)

    WDS Configuration:
    + User                     $($Config.WDSUser)
    + Mode                     $($Config.WDSMode)
    + Remote Install Path      $($Config.RemInstall)
    + Answer to Clients        $($Config.AnswerClients)
    + PXE Policy Known         $($Config.PxepromptKnown)
    + PXE Policy New           $($Config.PxepromptNew)
    + Use DHCP                 $($Config.UseDhcpPorts)

    MDT Configuration:
    + Source Root Path         $($Config.SourceRoot)
    + ADK Setup File           $($Config.ADKSetup)
    + WinPE Setup File         $($Config.WinPESetup)
    
    + ADK Install Path         $($Config.ADKInstPath)
    + ADK x86 Dst              $($Config.ADKx86Dst)

    + MDT Setup File           $($Config.MDTSetup)
    + MDT Patch File           $($Config.MDTPatch)
    + MDT Patch Extraction     $($Config.MDTExtractDir)
    + MDT Module               $($Config.MDTModule)

    + Deployment Share Path    $($Config.DeploymentShare)
    + Deployment Share Name    $($Config.DSName)
    + Administrative Share     $($Config.DeploymentShareName)
    + Share Description        $($Config.DeploymentShareDesc)
    + Log Share Path           $($Config.MDTLogShare)
    + Log Share Name           $($Config.MDTLogName)
    + Log Share Description    $($Config.MDTLogDesc)
    + Optional Directories     $($Config.MDTDirs)

    + Boot Image Path          $($Config.BootImagePath)
    + Image File               $($Config.ImageFile)
    + Image Name               $($Config.ImageName)
    + Image Description        $($Config.ImageDesc)

    + Use WSUS                 $($Config.UseWSUS)
    + WSUS Server              $($Config.WSUSServer)

    + Organization Name        $($Config.SMSTSOrgName)
    + Package Name             $($Config.SMSTSPackageName)

    + Event Monitor            $($Config.MDTMonitor)
    + Event Port               $($Config.MDTMonitorEvent)
    + Data Port                $($Config.MDTMonitorData)
"
try {
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Initializing:" -PercentComplete 1
	Confirm-RootDir
	Write-Log "===== BEGIN WDS & MDT CONFIGURATION ====="

	if ($Interactive) {
		Initialize-InteractiveConfig
	}
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Initializing:" -PercentComplete 5
	Confirm-InstallFiles
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure WDS:" -PercentComplete 10
	New-WDSUser
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure WDS:" -PercentComplete 15
	Initialize-WDSMode
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure WDS:" -PercentComplete 20
	Start-ConfigureWDS
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure WDS:" -PercentComplete 25

	Install-ADK
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Installing Files:" -PercentComplete 30
	Install-WinPE
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Installing Files:" -PercentComplete 35
	Import-ADKx86
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Installing Files:" -PercentComplete 40

	Install-MDT
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Installing Files:" -PercentComplete 45
	Install-MDTPatch
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Installing Files:" -PercentComplete 50

	New-MDTFolders
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 55
	Set-MDTSharePermissions
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 60
	New-DeploymentShare
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 65
	New-LogShare
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 70

	#Set-MDTMonitoring
	Enable-MDTMonitoring
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 75

	Set-CustomSettingsIni
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 80
	Set-BootstrapIni
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Configure MDT:" -PercentComplete 85

	Update-DeploymentShare
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Finalizing:" -PercentComplete 90
	Update-WDSBootImage
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Finalizing:" -PercentComplete 95

	Write-Log "===== CONFIGURATION COMPLETED ====="
	Write-Progress -id 1 -Activity "Configure WDS and MDT" -Status "Finalizing:" -PercentComplete 100
} 
catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
    exit 1
}



