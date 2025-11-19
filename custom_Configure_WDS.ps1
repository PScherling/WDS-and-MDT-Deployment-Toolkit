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
       - Copies x86 WinPE platform files

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
          Modified: 2025-11-19

          Version - 0.0.1 - () - Finalized functional version 1.
          

          TODO:

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

# =====================================================================
# GLOBAL CONFIG OBJECT
# =====================================================================

$Config = [PSCustomObject]@{
    Feature         = "WDS"
	Version         = "0.0.1"
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

    SourceRoot      = "C:\_it\WDS Files"
    ADKSetup        = "C:\_it\WDS Files\ADK\win11_24h2_adksetup_dez24.exe"
    WinPESetup      = "C:\_it\WDS Files\ADK\win11_24h2_adkwinpesetup_dez24.exe"
	ADKInstPath     = "D:\WindowsKits\ADK"

    ADKx86Src       = "C:\_it\WDS Files\ADK\Windows PE Environment\x86"
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

	UseWSUS         = "n"
	WSUSServer      = ""

	SMSTSOrgName    = "Company"
	SMSTSPackageName = "Windows Deployment System"

	MDTMonitor      = $env:COMPUTERNAME
	MDTMonitorEvent = 9800
	MDTMonitorData  = 9801

    LogDir          = "C:\_it"
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
	$UseWSUS = Read-Host "Do you want to use a WSUS server (default: no)? (y/n)"
	if ($UseWSUS -eq "y")
	{
		$Config.UseWSUS = "y"
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

    try {
        & $Code
    }
    catch {
        Write-Log "$Action failed: $_" "ERROR"
    }
}

# =====================================================================
# WDS FUNCTIONS
# =====================================================================

function New-WDSUser {
	$ok = $true
    Write-Log "Creating WDS service user '$($Config.WDSUser)'"
	$securePW = ConvertTo-SecureString $Config.WDSPassword -AsPlainText -Force

	try{
		Invoke-Safe {
			New-LocalUser -Name $Config.WDSUser `
				-Password $securePW `
				-AccountNeverExpires `
				-UserMayNotChangePassword `
				-FullName "Windows Deployment User" `
				-Description "Windows Deployment User" | Out-Null
		} "Create local WDS user"
	}
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Creating WDS service user succeed" "OK"
		}
		else{
			Write-Log "Creating WDS service user failed: $_" "ERROR"
		}
	}
}

function Initialize-WDSMode {
	$ok = $true
    Write-Log "Initializing WDS Mode."
	
	try{
		Invoke-Safe {
			wdsutil /Initialize-Server /Server:localhost /$($Config.WDSMode) /reminst:"$($Config.RemInstall)" 1>$null 2>&1
		} "WDS initialization"
	}
	catch{
		
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Initializing WDS Mode succeed" "OK"
		}
		else{
			Write-Log "Initializing WDS Mode failed: $_" "ERROR"
		}
	}
}

function Start-ConfigureWDS {
	$ok = $true

    Write-Log "Configuring WDS"
	try{
		Invoke-Safe { wdsutil /Set-Server /AnswerClients:$($Config.AnswerClients) 1>$null 2>&1 } "Set WDS to answer ALL clients"
		Invoke-Safe { wdsutil /Set-Server /PxePromptPolicy /Known:$($Config.PxePromptKnown) 1>$null 2>&1 } "PXE known = NoPrompt"
		Invoke-Safe { wdsutil /Set-Server /PxePromptPolicy /New:$($Config.PxePromptNew) 1>$null 2>&1 } "PXE new = NoPrompt"
		Invoke-Safe { wdsutil /Set-Server /UseDhcpPorts:$($Config.UseDhcpPorts) 1>$null 2>&1 } "Disable WDS DHCP port listening"
		#Invoke-Safe { wdsutil /Set-Server /DhcpOption60:$($Config.DhcpOption60) 1>$null 2>&1 } "Disable WDS DHCP Option listening"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Configuring WDS succeed" "OK"
		}
		else{
			Write-Log "Configuring WDS failed: $_" "ERROR"
		}
	}
}

# =====================================================================
# ADK FUNCTIONS
# =====================================================================

function Install-ADK {
	$ok = $true
    if (-not (Confirm-Step "Install Windows ADK?")) { return }

    Write-Log "Installing Windows 11 ADK"
	
	try{
		Invoke-Safe {
			Start-Process -FilePath "$($Config.ADKSetup)" `
				-ArgumentList "/quiet /norestart /ceip off /installpath $($Config.ADKInstPath) /features OptionId.DeploymentTools OptionId.UserStateMigrationTool" `
				-Wait -NoNewWindow
		} "Install W11 ADK"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Installing Windows 11 ADK succeed" "OK"
		}
		else{
			Write-Log "Installing Windows 11 ADK failed: $_" "ERROR"
		}
	}
}

function Install-WinPE {
	$ok = $true
    if (-not (Confirm-Step "Install WinPE?")) { return }

    Write-Log "Installing W11 WinPE Addon"
	try{
		Invoke-Safe {
			Start-Process -FilePath "$($Config.WinPESetup)" `
				-ArgumentList "/quiet /norestart /ceip off /installpath $($Config.ADKInstPath) /features OptionId.WindowsPreinstallationEnvironment" `
				-Wait -NoNewWindow
		} "Install W11 WinPE"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Installing W11 WinPE Addon succeed" "OK"
		}
		else{
			Write-Log "Installing W11 WinPE Addon failed: $_" "ERROR"
		}
	}
}

function Import-ADKx86 {
	$ok = $true
    Write-Log "Copying ADK x86 files"
	<#
	try{
		Invoke-Safe {
			if (-not (Test-Path "$($Config.ADKx86Dst)")) {
				New-Item -ItemType Directory -Path "$($Config.ADKx86Dst)" -Force | Out-Null
			}
		} "Create ADK x86 destination directory"
	}
	catch{
		Write-Log "Create ADK x86 destination directory failed: $_" "ERROR"
	}
	#>

	try{
		Invoke-Safe {
			Copy-Item -Path "$($Config.ADKx86Src)" -Destination "$($Config.ADKx86Dst)" -Recurse -Force | Out-Null
		} "Copy ADK x86 files"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Copy ADK x86 files succeed" "OK"
		}
		else{
			Write-Log "Copy ADK x86 files failed: $_" "ERROR"
		}
	}
}

# =====================================================================
# MDT FUNCTIONS
# =====================================================================

function Install-MDT {
	$ok = $true
    if (-not (Confirm-Step "Install MDT?")) { return }

    Write-Log "Installing MDT"
	try{
		Invoke-Safe {
			Start-Process msiexec.exe -Wait -WorkingDirectory $PSScriptRoot -ArgumentList "/i `"$($Config.MDTSetup)`" /qn /norestart"
		} "Install MDT"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Installing MDT succeed" "OK"
		}
		else{
			Write-Log "Installing MDT failed: $_" "ERROR"
		}
	}
}

function Install-MDTPatch {
	$ok = $true
    Write-Log "Extracting MDT patch"

	try{
		Invoke-Safe {
			Start-Process -FilePath "$($Config.MDTPatch)" -ArgumentList "-q", "-extract:`"$($Config.MDTExtractDir)`"" -Wait
		} "Extract MDT patch"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Extracting MDT patch succeed" "OK"
		}
		else{
			Write-Log "Extracting MDT patch failed: $_" "ERROR"
		}
	}

    Write-Log "Copying Patch Files"
	$ok = $true
	try{
		Invoke-Safe {
			Copy-Item "$($Config.MDTExtractDir)\x64\*" "$env:ProgramFiles\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x64" -Force
			Copy-Item "$($Config.MDTExtractDir)\x86\*" "$env:ProgramFiles\Microsoft Deployment Toolkit\Templates\Distribution\Tools\x86" -Force
		} "Copy MDT patch files"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Copying Patch Files succeed" "OK"
		}
		else{
			Write-Log "Copying Patch Files failed: $_" "ERROR"
		}
	}
}

function New-MDTFolders {
    Write-Log "Creating MDT directories"
	

    foreach ($dir in $Config.MDTDirs) {
		$ok = $true
		try{
			Invoke-Safe {
				if (-not (Test-Path "$($dir)")) {
					New-Item -ItemType Directory -Path "$($dir)" -Force | Out-Null
				}
			} "Create directory $($dir)"
		}
		catch{
			$ok = $false
			
		}
		finally{
			if($ok){
				Write-Log "Create directory $($dir) succeed" "OK"
			}
			else{
				Write-Log "Create directory $($dir) failed: $_" "ERROR"
			}
		}
    }
}

function Set-MDTSharePermissions {
    Write-Log "Setting NTFS and Share permissions"

    foreach ($dir in $Config.MDTDirs) {
		$ok = $true
        # Share creation
        $shareName = Split-Path $dir -Leaf
		try{
			Invoke-Safe {
				New-SmbShare -Name "$($shareName)" -Path "$($dir)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
			} "Create share $($shareName)"
		}
		catch{
			$ok = $false
			
		}
		finally{
			if($ok){
				Write-Log "Create share $($shareName) succeed" "OK"
			}
			else{
				Write-Log "Create share $($shareName) failed: $_" "ERROR"
			}
		}

        # NTFS Permissions
		$ok = $true
		try{
			Invoke-Safe {
				icacls $dir /grant '"Users":(OI)(CI)(RX)' | Out-Null
				icacls $dir /grant '"Administrators":(OI)(CI)(F)' | Out-Null
				icacls $dir /grant '"SYSTEM":(OI)(CI)(F)' | Out-Null
				icacls $dir /grant `"$($Config.CompName)\$($Config.WDSUser)`"':(OI)(CI)(M)' | Out-Null
			} "Set NTFS permissions for $($dir)"
		}
		catch{
			$ok = $false
			
		}
		finally{
			if($ok){
				Write-Log "Set NTFS permissions for $($dir) succeed" "OK"
			}
			else{
				Write-Log "Set NTFS permissions for $($dir) failed: $_" "ERROR"
			}
		}
    }
}

function New-DeploymentShare {
    Write-Log "Creating MDT Deployment Share"
	$ok = $true
    # Folder
	try{
		Invoke-Safe {
			if (-not (Test-Path $Config.DeploymentShare)) {
				New-Item -ItemType Directory -Path "$($Config.DeploymentShare)" -Force | Out-Null
			}
		} "Create DeploymentShare folder"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Create DeploymentShare folder succeed" "OK"
		}
		else{
			Write-Log "Create DeploymentShare folder failed: $_" "ERROR"
		}
	}

    # Share
	$ok = $true
	try{
		Invoke-Safe {
			New-SmbShare -Name "$($Config.DeploymentShareName)" -Path "$($Config.DeploymentShare)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
		} "Create MDT share"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Create MDT share succeed" "OK"
		}
		else{
			Write-Log "Create MDT share failed: $_" "ERROR"
		}
	}

    # MDT PSDrive (will only work if MDT provider is functioning)
	Import-Module $Config.MDTModule -ErrorAction Stop
	$ok = $true
	try{
		Invoke-Safe {
			New-PSDrive -Name "$($Config.DSName)" -PSProvider "MDTProvider" -Root "$($Config.DeploymentShare)" -Description "$($Config.DeploymentShareDesc)" -Scope Global | Add-MDTPersistentDrive | Out-Null
		} "Create MDT PSDrive"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Create MDT PSDrive succeed" "OK"
		}
		else{
			Write-Log "Create MDT PSDrive failed: $_" "ERROR"
		}
	}
}

function New-LogShare {
    Write-Log "Creating MDT Log Share"
	$ok = $true
    # Folder
	try{
		Invoke-Safe {
			if (-not (Test-Path $Config.MDTLogShare)) {
				New-Item -ItemType Directory -Path "$($Config.MDTLogShare)" -Force | Out-Null
			}
		} "Create Log Share folder"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Create Log Share folder succeed" "OK"
		}
		else{
			Write-Log "Create Log Share folder failed: $_" "ERROR"
		}
	}

    # Share
	$ok = $true
	try{
		Invoke-Safe {
			New-SmbShare -Name "$($Config.MDTLogName)" -Path "$($Config.MDTLogShare)" -FullAccess Administrators -ChangeAccess Everyone | Out-Null
		} "Create MDT Log share"
	}
	catch{
		$ok = $false
		
	}
	finally{
		if($ok){
			Write-Log "Create MDT Log share succeed" "OK"
		}
		else{
			Write-Log "Create MDT Log share failed: $_" "ERROR"
		}
	}

}

<#
function Set-MDTMonitoring {
	Write-Log "Configure Event Monitoring Service"
	# Enable Event Monitoring
	$ok = $true
	try{
		Invoke-Safe {
			Set-MDTMonitorData -Server "$($Config.MDTMonitor)" -EventPort $($Config.MDTMonitorEvent) -DataPort $($Config.MDTMonitorData) | Out-Null
		} "Set event monitoring configuration"
	} 
	catch{
		$ok = $false
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
	$ok = $true
	try{
		Invoke-Safe {
			Enable-MDTMonitorService -EventPort $($Config.MDTMonitorEvent) -DataPort $($Config.MDTMonitorData) | Out-Null
		} "Enable Event Monitoring Service"
	} 
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Enable Event Monitoring Service succeed" "OK"
		}
		else{
			Write-Log "Enable Event Monitoring Service failed: $_" "ERROR"
		}
	}
}

function Set-CustomSettingsIni {
	## MDT configuration
    ## Build share CustomSettings.ini

	Write-Log "Build MDT Deployment Share 'CustomSettings.ini'"
	$ok = $true

	try{
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
			Add-Content -Path "$($Config.DeploymentShare)\Control\CustomSettings.ini" -Value "WSUSServer=http://$($Config.WSUSServer):8530"
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
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Build MDT Deployment Share 'CustomSettings.ini' succeed" "OK"
		}
		else{
			Write-Log "Build MDT Deployment Share 'CustomSettings.ini' failed: $_" "ERROR"
		}
	}
}

function Set-BootstrapIni {
	## MDT configuration
    ## Build share Bootstrap.ini

	Write-Log "Build MDT Deployment Share 'Bootstrap.ini'"
	$ok = $true

	try{
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
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Build MDT Deployment Share 'Bootstrap.ini' succeed" "OK"
		}
		else{
			Write-Log "Build MDT Deployment Share 'Bootstrap.ini' failed: $_" "ERROR"
		}
	}
}

function Update-DeploymentShare {
	Write-Log "Updating Deployment Share and generating boot media"
	$ok = $true

	try{
		Invoke-Safe {
			Update-MDTDeploymentShare -Path "$($Config.DSName):" -Force | Out-Null
		} "Update DeploymentShare"
	}
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Update DeploymentShare succeed" "OK"
		}
		else{
			Write-Log "Update DeploymentShare failed: $_" "ERROR"
		}
	}
}

function Update-WDSBootImage {
	Write-Log "Updating WDS Boot Image"
	$ok = $true

	try{
		Invoke-Safe {
			Import-WdsBootImage -Path "$($Config.BootImagePath)\$($Config.ImageFile)" -NewImageName "$($Config.ImageName)" -NewFileName "$($Config.ImageFile)" -NewDescription "$($Config.ImageDesc)" -SkipVerify
		} "Update DeploymentShare"
	}
	catch{
		$ok = $false
	}
	finally{
		if($ok){
			Write-Log "Update DeploymentShare succeed" "OK"
		}
		else{
			Write-Log "Update DeploymentShare failed: $_" "ERROR"
		}
	}
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
    + ADK x86 Src              $($Config.ADKx86Src)
    
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
Write-Log "===== BEGIN WDS & MDT CONFIGURATION ====="

if ($Interactive) {
    Initialize-InteractiveConfig
}

New-WDSUser
Initialize-WDSMode
Start-ConfigureWDS

Install-ADK
Install-WinPE
Import-ADKx86

Install-MDT
Install-MDTPatch

New-MDTFolders
Set-MDTSharePermissions
New-DeploymentShare
New-LogShare

#Set-MDTMonitoring
Enable-MDTMonitoring

Set-CustomSettingsIni
Set-BootstrapIni

Update-DeploymentShare
Update-WDSBootImage

Write-Log "===== CONFIGURATION COMPLETED ====="
