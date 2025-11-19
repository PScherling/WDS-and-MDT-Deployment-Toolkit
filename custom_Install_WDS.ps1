<#
.SYNOPSIS
    Installs and configures the Microsoft Windows Deployment Services (WDS) role and its management tools.
	
.DESCRIPTION
    The **custom_Install_WDS.ps1** script automates the installation of the **Windows Deployment Services (WDS)** role 
	and associated management tools on a Windows Server system.  
	
	
	
	
	
	

.LINK
    
	https://github.com/PScherling
	
.NOTES
          FileName: custom_Install_WDS.ps1
          Solution: Install MS WDS Roles and Features
          Author: Patrick Scherling
          Contact: @Patrick Scherling
          Primary: @Patrick Scherling
          Created: 2025-11-17
          Modified: 2025-11-17

          Version - 0.0.1 - () - Finalized functional version 1.
          

          TODO:

.Requirements
	
		
.Example
	PS> .\custom_Install_WDS.ps1
	Installs the WDS server role and management tools with logging to both local and remote paths.
	
	PS> powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\custom_Install_WDS.ps1"
	Executes unattended during deployment or server provisioning for automatic WDS setup.
#>
$feature = "WDS"

# Log file path and function to log messages
$SrvIP = "192.168.121.66" # MDT Server IP-Address
$CompName = $env:COMPUTERNAME
$DateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$logFileName = "Install_$($feature)_$($CompName)_$($DateTime).log"

$logFilePath = "\\$($SrvIP)\Logs$\Custom\RolesAndFeatures"
$logFile = "$($logFilePath)\$($logFileName)"

$localLogFilePath = "C:\_it"
$localLogFile = "$($localLogFilePath)\$($logFileName)"



function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $Message" | Out-File -FilePath $localLogFile -Append
}

Write-Log "Start Logging."

# Create required directories
Write-Log "Create required directories."
$directories = @(
	"C:\_it"
)

foreach ($dir in $directories) {
	Write-Log "Directory '$dir' already exists."
	If (-not (Test-Path $dir)) { 
		Write-Log "Creating Directory '$dir'."
		try{
			New-Item -Path $dir -ItemType Directory
		}
		catch{
			Write-Log "ERROR: Directory '$dir' could not be created."
		}
	}
}

<#
# Application Install
#>
Write-Log "Installing Roles and Features '$($feature)'."
try{
	Install-WindowsFeature -Name WDS-Deployment -IncludeManagementTools #-Restart
}
catch{
	Write-Warning "$_"
	Write-Log "ERROR: Roles and Features '$($feature)' could not be installed.
	Reason: $_"
}

Write-Log "Finish Logging."
<#
# Finalizing
#>
# Upload logFile
try{
	Copy-Item "$localLogFile" -Destination "$logFilePath"
}
catch{
	Write-Warning "ERROR: Logfile '$localLogFile' could not be uploaded to Deployment-Server.
	Reason: $_"
}

# Delete local logFile
try{
	Remove-Item "$localLogFile" -Force
}
catch{
	Write-Warning "ERROR: Logfile '$localLogFile' could not be deleted.
	Reason: $_"
}