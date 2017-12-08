<#
.SYNOPSIS
GMI NetBackup Client Install
Aaron Kopel/Jason Whitelock

.DESCRIPTION
This script helps to automate and guide a technician through installing the NetBackup Client on a server
at General Mills and optionally registering it with a Netbackup Master Server.
Script Runs interactively by default, but can be automated with standard parameters

.PARAMETER	InstallType
Specifies whether to Install,Reinstall,ForceInstall, or ForceReinstall
Install will Install the Client and register it with the Master Server
Reinstall will Install the Client and NOT register it with the Master Server
ForceInstall/ForceReinstall will ignore VMware-Backups based sites and install the client anyways

.PARAMETER	MasterServer
This must be the name of a NetBackup master server. This is not required
and only needed if it is desired to override the normal site-based Master server
selection process. (NOT COMMON)

.PARAMETER	Policy
This is the name of the Netbackup policy. This is not required and only needed
if it is desired to override the normal site-based default Policy selection (NOT COMMON)

.EXAMPLE
PS C:\> NBU-ClientInstall.ps1 -InstallType Install

.EXAMPLE
PS C:\> NBU-ClientInstall.ps1 -InstallType Reinstall -MasterServer mgobpmasp1

.EXAMPLE
PS C:\> NBU-ClientInstall.ps1 -InstallType Install -MasterServer mgobpmasp1 -Policy T-SpecialPolicy
#>
[cmdletbinding()]
param(
	[ValidateSet('Install','Reinstall','ForceInstall','ForceReinstall')]
	[System.String]$InstallType,
	[System.String]$MasterServer,
	[System.String]$Policy,
	[switch]$TestRun
)

$Version = "4.0"
$LastUpdate = "05/19/2016"

#region Change Log
## Ver 2.6 - exclusion logic for W2K12
## Ver 2.7 - added logic to handle gmfcu.com as masterserver
## Ver 2.8 - Shortened Subject for better fit on phone screen
## Ver 2.8.1 - Changed logic to gather ADSite to work with PowerShell 3.0 due to bug in registry retrive of DynamicSiteName
## Ver 2.8.2 - Changed OSType to 'Windows' (vs Windows2003/Windows2008). NBU7.5.0.6 handles it generically now. Changed to use Timestamp vs Archive Bit
## Ver 2.8.3 - Updated logic to handle mstgenmills and point to mstbkp1 instead of mgotstbkp1
## Ver 2.8.4 - Handle gmfcu
## Ver 2.9.0 - Added in logic to allow W2K12R2 (Requires NBU 7.6.0.x at Master Server Site)
## Ver 2.9.1 - Fixed VMware Site Detection Bug
## Ver 2.9.2 - Fixed Site Detection with extgenmills so MGO does VMware Backups and CNQK does 'normal'
## Ver 3.0.0 - Convert script to use proper [cmdletbinding()] parameters and use NetBackup Powershell module
##			 - Added new InstallType flags ForceInstall and ForceReinstall to override VMware-Site Skip behavior
##			 - Added $TestRun switch to script to test only
## Ver 3.0.1 - Changed Path to NetBackup PowerShell Module
## Ver 3.0.2 - Updated OSVersion Check to handle Window Server 2016
## Ver 4.0   - Tweaked to work in azugenmills
#endregion

#region Load PowerShell Modules
Write-Host "[Loading NetBackup Module]" -ForegroundColor Cyan
Import-Module '\\azubkp1.azugenmills.com\MSTShared\Scripts\PowerShellModules\NetBackup' -Force -ErrorAction Continue
#endregion

#region Application Functions

########################################################################################
### Send-Results (Sends Installation results and cleans up installation directory)
########################################################################################
Function Send-Results {
	Write-Host "`n[Initializing Status Reporting and Cleanup]" -ForegroundColor Cyan
	if ($InstallStatus -eq $null) { $InstallStatus = "Unknown" }
	if ($InstallType -eq $null) { $InstallType = "Install" }
	
	## Create Subject and Body based on result
	if ($MasterServer -eq $null) { 
		$Subject = "NBUClient $InstallType $InstallStatus [ $ClientName ]" 
	} else {
		$Subject = "NBUClient $InstallType $InstallStatus [ $ClientName on $MasterServer ]"
	}
	
	$Body = @()
	$Body += "****************************************"
	$Body += " NetBackup Client Installation Summary"
	$Body += "****************************************"
	$Body += "Server:            $ServerFQDN"
	$Body += "NBUClient Name:    $ClientName"
	$Body += "Master Server:     $MasterServer"
	$Body += "Custom Policy:     $Policy"
	$Body += "Technician:        $UserDomain\$UserLogin"
	$Body += "Date Completed:    $Today"
	$Body += "OS Version:        $OSVersion"
	$Body += "OS Architecture:   $Arch"
	$Body += "Version Installed: $InstalledVersion"
	if ($FailureReason) {
		$Body += "Failure Reason:    $FailureReason"
	}
	if ($Unattended) {
		$Body += "Unattened Install: $Unattended (Parameters: .\NBU-ClientInstall $Script:args)"
	} else {
		$Body += "Unattened Install: $Unattended"
	}
	# Write-Host "-> Emailing results to NBU Admins" -ForegroundColor Green
	## Send Summary to NBUAdmins
	# Send-MailMessage -To $MailAdmins -From $From -Subject $Subject -Body ($Body | Out-String) -SmtpServer $SMTP
	
	## Cleanup Installation Directory
	Write-Host "-> Removing NetBackup Client Installation Files" -ForegroundColor Green
	Set-Location "C:\" -ErrorAction SilentlyContinue
	Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
	
	Write-Host "`n***************************************" -ForegroundColor Cyan
	Write-Host "** NBU Client Installation Complete! **" -ForegroundColor Cyan
	Write-Host "***************************************" -ForegroundColor Cyan
	if (!($Unattended)) {
		Read-Host "Press <enter> to exit"
	}
	exit
}


#######################################################################
### Test-PSVersion (Tests for proper version of PowerShell)
#######################################################################
Function Test-PSVersion { 
    Write-Host "[Checking for proper version of Powershell]" -ForegroundColor Cyan
    if ($Host.Version.Major -lt "2") {
        Write-Warning "*********************************************************************************************"
        Write-Warning "**  Powershell 2.0 is required to complete PostBuild, please install it and try again        "
        Write-Warning "**  Please contact IT-WINDOWS OPERATIONS & TECH SUPPORT or call 763-764-2660 for assistance  "
        Write-Warning "**                                                                                           "
        Write-Warning "**  Install is now exiting                                                                   "
        Write-Warning "*********************************************************************************************"
		Start-Sleep 5
        exit
    }
}

###############################################################################
### Test-Writable (Tests if directory is writable)
###############################################################################
Function Test-Writable {
	param(
		[parameter(Mandatory=$true)]
		[string]$Directory
	)
	$TestFile = "TestFile-$ServerName.txt"
	
	# Verify Directory exists
	Write-Host "Validating Directory exists... " -NoNewline
	if ((Test-Path $Directory -ErrorAction SilentlyContinue) -ne $true) { 
		Write-Host "ERROR: Cannot reach $Directory" -ForegroundColor Yellow
		return $false 
	}
	
	# Try creating TestFile
	Write-Host "Attempting to create TestFile... " -NoNewline
	$WriteResult = New-Item -Name $TestFile -ItemType file -Path $Directory -Force -ErrorAction SilentlyContinue
	if ($WriteResult) { 
		Write-Host "Removing TestFile..." -NoNewline
		Remove-Item -Path $Directory\$TestFile -Force -ErrorAction SilentlyContinue
		return $true
	} else {
		Write-Host "ERROR: Cannot write $Directory\$TestFile" -ForegroundColor Yellow -NoNewline
		return $false
	}
}

###############################################################################
### Change-ClientName (Changes and validates the ClientName)
###############################################################################
Function Change-ClientName {
	Do {
	  	Write-Host "***************************************************************************"
		do {
			$Client = (Read-Host "Type the FQDN of the new ClientName (e.g. $ServerName-bkp.genmills.com)").tolower()
		} while ($Client -eq "")
		
		if ($Client -notmatch ".genmills.com") {
			Write-Host "NOTE: It is recommended to use FQDN for NetBackup Client Names" -ForegroundColor Yellow
			do {
				$choice = Read-Host "Would you like to append '.genmills.com' to the client name? (y/n)[y]"
				if ($choice -eq "") { $choice = "y" }
			} while (($choice -ne "y") -and ($choice -ne "n"))
			if ($choice -eq "y") { $Client += ".genmills.com" }
		}
		
		## Test Ping Connectivity to New Client Name
		Write-Host "[Attempting to ping $Client]" -ForegroundColor Cyan
		if (Test-Connection $Client -Count 2 -Quiet) {
			Write-Host "-> Ping to $Client was successful!" -ForegroundColor Green
		} else {
			Write-Host "`nWarning: Unable to ping $Client!" -ForegroundColor Red
			Write-Host "TIP: Please verify the backup nic is configured correctly and setup in DNS." -ForegroundColor Yellow
			Write-Host "If you continue to experince problems, please contact IT-WINDOWS OPERATIONS & TECH SUPPORT or call 763-764-2660." -ForegroundColor Red
			Write-Host "** PowerShell Command used for test: 'Test-Connection $Client'" -ForegroundColor Red
			Write-Host
			$choice = Read-Host "Press <enter> to re-enter ClientName or type 'ignore' to use this ClientName anyways (NOT RECOMMENDED)"
			
			if ($choice -ne "ignore") {
				$Client = $null
			} 
		}
	} while (!$Client)
	$Script:ClientName = $Client
}

#################################################################################
### Select-MasterServer (Prompts for MasterServer and tests for proper connectivity)
#################################################################################
Function Select-MasterServer {
	param(
		[string]$Master
	)
	do {
		Write-Host "***************************************************************************"
		While (($Master -eq $null) -or ($Master -eq "")) {
			if ($Unattended) {
				$InstallStatus = "Failed"
				$FailureReason = "No MasterServer passed to Select-MasterServer Function"
				(Send-Results)
			} else {
				$Master = Read-Host "Type the Master Server for this client (e.g. <site>bkp1)"
			}
	 	}
		
		if ($Master -notlike "*.*.com") {
			$Master += ".genmills.com"
		}
		
		$Script:NewClientsPath = "\\$Master\NBUClientInstall$\Clients2Process\CurrentDay"
		$Script:SourceFiles = "\\$Master\NBUClientInstall$\CurrentClientInstall\$Arch-files"
		$ClientInstallShare = "\\$Master\NBUClientInstall$"
		
		## Test Ping Connectivity to Master Server
		Write-Host "[Attempting to ping $Master]" -ForegroundColor Cyan
		if (Test-Connection $Master -Count 2 -Quiet) {
			Write-Host "-> Ping to $Master was successful!" -ForegroundColor Green
			if (!($Unattended)) {
				# Attempt to Authenticate
				Write-Host "[Attempting UNC connection to $Master]" -ForegroundColor Cyan
				Write-Host "If prompted, enter Domain Credentials (e.g. genmills\a9999zz)" -ForegroundColor Yellow
				(net use $ClientInstallShare /delete 2> $null) | Out-Null
				net use $ClientInstallShare
				sleep 2
			}
		} else {
			Write-Host
			Write-Host "`nWarning: Unable to ping $Master!" -ForegroundColor Red
			Write-Host "Please check your network connection and try again." -ForegroundColor Red
			Write-Host "If you continue to experince problems, please contact IT-WINDOWS OPERATIONS & TECH SUPPORT or call 763-764-2660." -ForegroundColor Yellow
			Write-Host "** PowerShell Command used for test: 'Test-Connection $Master'" -ForegroundColor Red
			Write-Host
			if ($Unattended) {
				$InstallStatus = "Failed"
				$FailureReason = "Unable to ping MasterServer"
				$Script:MasterServer = $Master
				(Send-Results)
			} else {
				$choice = Read-Host "Press <enter> to start again or type 'skip' to attempt authentication anyways (NOT RECOMMENDED)"
			}		
			if ($choice -eq "skip") {
				# Attempt to Authenticate
				Write-Host "[Attempting UNC connection to $Master]" -ForegroundColor Cyan
				Write-Host "If prompted, enter Domain Credentials (e.g. genmills\a9999zz)" -ForegroundColor Yellow
				(net use $ClientInstallShare /delete 2> $null) | Out-Null
				net use $ClientInstallShare
				sleep 2
			} else {
				$Master = $null
			}
		}
		
		if ($Master) {
			## Test that SourceFiles Exist
			Write-Host "[Checking connection to SourceFiles]" -ForegroundColor Cyan
			if (Test-Path $SourceFiles -ErrorAction SilentlyContinue) {
				Write-Host "-> Connection to SourceFiles was successful!" -ForegroundColor Green
			} else {
				Write-Host
				Write-Host "`nERROR!! Unable to access SourceFiles" -ForegroundColor Red
				Write-Host "Please check your network connection and try again." -ForegroundColor Red
				Write-Host "If you continue to experince problems, please contact IT-MICROSOFT SERVER TECHNOLOGIES DISTLIST" -ForegroundColor Yellow
				Write-Host "** Path Not Found: $SourceFiles" -ForegroundColor Red
				Write-Host
				if ($Unattended) {
					$InstallStatus = "Failed"
					$FailureReason = "Unable to access SourceFiles on MasterServer"
					$Script:MasterServer = $Master
					Start-Sleep 5
					(Send-Results)
				} else {
					Read-Host "Press <enter> to start again"
					$Master = $null
				}
			}
		}	
		
		if ($Master) {
			## Test that NewClientsPath is writable
			Write-Host "[Checking connection to NewClientsPath]" -ForegroundColor Cyan
			if (Test-Writable $NewClientsPath) {
				Write-Host "`n-> Writability to New Clients Path was successful!" -ForegroundColor Green
			} else {
				Write-Host
				Write-Host "`nERROR!! Unable to access NewClients Path" -ForegroundColor Red
				Write-Host "Please check your network connection and try again." -ForegroundColor Red
				Write-Host "If you continue to experince problems, please contact IT-WINDOWS OPERATIONS & TECH SUPPORT or call 763-764-2660." -ForegroundColor Yellow
				Write-Host "** Path Not Writable: $NewClientsPath" -ForegroundColor Red
				Write-Host
				if ($Unattended) {
					$InstallStatus = "Failed"
					$FailureReason = "Unable to write to NewClientsPath on MasterServer"
					$Script:MasterServer = $Master
					(Send-Results)
				} else {
					Read-Host "Press <enter> to start again"
					$Master = $null
				}
			}
		}
	} while (!$Master)	
	$Script:MasterServer = $Master
}

#endregion Application Functions

#region Initialize Base Variables
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$TempDir = "C:\Cleanup\NBUInstall"

## Get Current ServerName, Date etc
$ServerName = (Get-Content env:computername).tolower()
$Today = (Get-Date -uformat %m/%d/%Y).ToString()
$UserLogin = (Get-Content env:username).tolower()

## Get Hardware Architecture and OS Version
if (Test-Path C:\Windows\SysWOW64) { $Arch = "x64" } else { $Arch = "x86" }
$OSVersion = [decimal](((Get-WmiObject Win32_OperatingSystem).Version).split('.')[0,1] -join '.')

## Check for Proper PowerShell Version
(Test-PSVersion)

## Set PowerShell WindowSize, BufferSize and WindowTitle
$NewBufferHeight = 3000
$NewBufferWidth = 130
$NewWindowHeight = 55
$NewWindowWidth = 130

$pshost = Get-Host
$pswindow = $pshost.ui.rawui
$pswindow.WindowTitle = $ProgramName

# Init Buffer/WindowSize with 'current' Values
$NewBufferSize = $pswindow.BufferSize
$NewWindowSize = $pswindow.WindowSize

# Check if BufferSize and WindowSize Dimensions are already big enough or not
if ($pswindow.Buffersize.Height -lt $NewBufferHeight) {
	$NewBufferSize.Height = $NewBufferHeight
}
if ($pswindow.Buffersize.Width -lt $NewBufferWidth) {
	$NewBufferSize.Width = $NewBufferWidth
}
if ($pswindow.WindowSize.Height -lt $NewWindowHeight) {
	$NewWindowSize.Height = $NewWindowHeight
}
if ($pswindow.WindowSize.Width -lt $NewWindowWidth) {
	$NewWindowSize.Width = $NewWindowWidth
}

# Make the BufferSize/WindowSize Change
$pswindow.BufferSize = $NewBufferSize
$pswindow.WindowSize = $NewWindowSize
#endregion

###############################################################################
### MAIN CODE
###############################################################################
Write-Host  "******************************************" -ForegroundColor Cyan
Write-Host  "* GMI Azure NetBackup Client Install  " -ForegroundColor Cyan
Write-Host  "* Version $Version                        " -ForegroundColor Cyan
Write-Host  "* Last Updated: $LastUpdate               " -ForegroundColor Cyan
if ($TestRun) {
	Write-Host  "*        ***** TestRun Mode *****         " -ForegroundColor Yellow
}
Write-Host  "******************************************" -ForegroundColor Cyan

## Check for Unattended Installation
Write-Host "[Checking for unattended installation]" -ForegroundColor Cyan
if ($InstallType) {
	$Unattended = $true
} else {
	$Unattended = $false 
}

Write-Host "-> Unattened:    $Unattended" -ForegroundColor Green
Write-Host "-> InstallType:  $InstallType" -ForegroundColor Green
Write-Host "-> MasterServer: $MasterServer" -ForegroundColor Green
Write-Host "-> Policy:       $Policy" -ForegroundColor Green

############################################
## Get Domain/Site/ClientName information
############################################
Write-Host "[Checking membership in a domain]" -ForegroundColor Cyan
if((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
	$ADDomain = ((Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain).tolower()
	$ADSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
	$UserDomain = (Get-Content env:userdomain).tolower()
	$ServerFQDN = "$ServerName.$ADDomain"
	Write-Host "-> ServerName:   $ServerName" -ForegroundColor Green
	Write-Host "-> Domain:       $ADDomain" -ForegroundColor Green
	Write-Host "-> ADSite:       $ADSite" -ForegroundColor Green
	Write-Host "-> UserLogin:    $UserDomain\$UserLogin" -ForegroundColor Green
} else {
	# Default to azugenmills.com
	$ADDomain = $null
	$ADSite = 'None'
	$UserDomain = $null
	$ServerFQDN = "$Servername" + ".azugenmills.com"
	Write-Host "-> Warning: No Domain Found! Defaulting to .azugenmills.com" -ForegroundColor Yellow
	Write-Host "-> ServerName:   $ServerName" -ForegroundColor Green
	Write-Host "-> Domain:       None" -ForegroundColor Green
	Write-Host "-> ADSite:       None" -ForegroundColor Green
	Write-Host "-> UserLogin:    $UserLogin" -ForegroundColor Green
}

## Set Initial NetBackup Client Name
Write-Host "[Generating initial NBU Client Name]" -ForegroundColor Cyan
$ClientName = $ServerFQDN
Write-Host "-> ClientName set to $ClientName" -ForegroundColor Green

########################################################
## Check if NetBackup Client is already installed
########################################################
if ((Get-Service "NetBackup Client Service" -ErrorAction SilentlyContinue) -or (Get-Service "Netbackup INET Daemon" -ErrorAction SilentlyContinue)) {
	Write-Warning "****************************************************************************"
    Write-Warning "**  NetBackup Client is already installed on this server                    "
    Write-Warning "**  If you would like to upgrade the client, please use the upgrade scripts "
    Write-Warning "**                                                                          "
    Write-Warning "**  Installation is now exiting                                             "
    Write-Warning "****************************************************************************"
	$InstallStatus = "Failed"
	$FailureReason = "NetBackup Client already installed"
	(Send-Results)
}

########################################################
## Get Master Server depending on site/domain topology
########################################################
if (!$MasterServer) {
    Write-Host "-> Setting master server" -ForegroundColor Green
    (Select-MasterServer "azubkp1.azugenmills.com")
}

########################################
## Welcome Section
########################################
if (!($Unattended)) {
	Do {
		Start-Sleep 2
		Clear-Host
		$tryagain = $false
		Write-Host  "******************************************" -ForegroundColor Cyan
		Write-Host  "* General Mills NetBackup Client Install  " -ForegroundColor Cyan
		Write-Host  "* Version $Version                        " -ForegroundColor Cyan
		Write-Host  "* Last Updated: $LastUpdate               " -ForegroundColor Cyan
		if ($TestRun) {
			Write-Host  "*        ***** TestRun Mode *****         " -ForegroundColor Yellow
		}
		Write-Host  "******************************************" -ForegroundColor Cyan
		Write-Host 
		Write-Host  "WHAT THIS PROGRAM DOES:" -ForegroundColor Yellow
		Write-Host 
		Write-Host  "> Installs the NetBackup Client on this server"
		Write-Host  "> Adds the client to the appropriate site backup policy"
		Write-Host  "*************************************************************************************************"
		Write-Host  "COMMANDS:" -ForegroundColor Green
		Write-Host  "1) Install:             " -f Yellow -NoNewline; Write-Host "Install client and add it to a default backup policy"
		Write-Host  "2) Re-Install:          " -f Yellow -NoNewline; Write-Host "Re-Install client and do NOT add it to a policy (For rebuilding a server)"
		Write-Host  "3) Change MasterServer: " -f Yellow -NoNewline; Write-Host "Change the generated Master server below"
		Write-Host  "4) Change ClientName:   " -f Yellow -NoNewline; Write-Host "For Servers with a dedicated backup nic (NOT COMMON)"
		Write-Host  "q) exit                 " -f Red
		Write-Host  "*************************************************************************************************"
		Write-Host  "MasterServer:  " -NoNewline
		Write-Host  $MasterServer.padright(38) -ForegroundColor Green -NoNewline
		Write-Host  " <--- PLEASE ENSURE THIS IS CORRECT!!!" -ForegroundColor Yellow
		Write-Host  "ClientName:    " -NoNewline
		Write-Host  $ClientName.padright(38) -ForegroundColor Green -NoNewline
		Write-Host  " <--- PLEASE ENSURE THIS IS CORRECT!!!" -ForegroundColor Yellow
		Write-Host  "-------------------------------------------------------------------------------------------------"
		Write-Host  "HostName:      " -NoNewline
		Write-Host  $ServerFQDN.padright(38) -ForegroundColor Green
		Write-Host  "ADSite:        " -NoNewline
		Write-Host  $ADSite.padright(38) -ForegroundColor Green
		Write-Host  "*************************************************************************************************"
		## Select Installation Option
		$choice = Read-Host "Verify Master & Client, then select command from above (1-4)"
		switch ($choice){
			1 { $InstallType = "Install" }
			2 { $InstallType = "Reinstall" }
			3 { (Select-MasterServer) ; $tryagain = $true }
			4 { (Change-ClientName) ; $tryagain = $true }
			q { write-host "Exiting" ; exit }
			default { Write-Host "Warning: Invalid Choice, try again" -ForegroundColor Yellow ; $tryagain = $true }
		} 
	} while ($tryagain -eq $true)
}

########################################
## Copy Files Section
########################################
Write-Host "[Removing old NetBackup Client Installation Files]" -ForegroundColor Cyan
Remove-Item C:\Cleanup\NBUINSTALL -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[Copying NetBackup Client Installation Files]" -ForegroundColor Cyan
(robocopy.exe $SourceFiles $TempDir /MIR)
Write-Host "-> Copy Complete" -ForegroundColor Green

########################################
## Installation Section
########################################
if (!$TestRun) {
	Write-Host "`n[Installing NetBackup Client]" -ForegroundColor Cyan
	Set-Location $TempDir
	Write-Host "-> Killing any running backups" -ForegroundColor Green
	Stop-Process -Name bpbkar32 -Force -ErrorAction SilentlyContinue
	Start-Sleep 3

	## Install BASE NBU Client
	if (Test-Path "$TempDir\BASE\Setup.exe" -ErrorAction SilentlyContinue) {
		$BaseVersion = (Get-ChildItem "$TempDir\BASE\Setup.exe").VersionInfo.ProductVersion
		Write-Host "-> Installing BASE NetBackup Client:      $BaseVersion     - Please wait" -ForegroundColor Green
		Start-Process -Wait silentclient.cmd -WorkingDirectory "$TempDir\Base" -WindowStyle Minimized
		Start-Sleep 5
	} else {
		Write-Host "Installation Files not found!" -ForegroundColor Yellow
		$InstallStatus = "Failed"
		$FailureReason = "Local Setup Files not foud: $TempDir\BASE\Setup.exe"
		(Send-Results)
	}

	## Install NBU Maint Pack
	if (Test-Path "$TempDir\MP\Setup.exe" -ErrorAction SilentlyContinue) {
		$MPVersion = (Get-ChildItem "$TempDir\MP\Setup.exe").VersionInfo.ProductVersion
		Write-Host "-> Installing NetBackup Maintenance Pack: $MPVersion - Please wait" -ForegroundColor Green
		Start-Process -Wait silentpatch.cmd -WorkingDirectory "$TempDir\MP" -WindowStyle Minimized
		Start-Sleep 5
	} else {
		Write-Host "-> No NBU Maintenance Pack found. Skipping" -ForegroundColor Green
	}

	## Install NBU Patches (EEBs)
	if (Test-Path "$TempDir\PATCH\installpatches.cmd" -ErrorAction SilentlyContinue) {
		Write-Host "-> Installing NetBackup Patches (EEBs) - Please wait" -ForegroundColor Green
		Start-Process -Wait installpatches.cmd -WorkingDirectory "$TempDir\PATCH" -WindowStyle Minimized -ErrorAction SilentlyContinue
		Start-Sleep 5
	} else {
		Write-Host "-> No NBU patches found. Skipping" -ForegroundColor Green
	}

	## Configure Client
	Write-Host "`n[Configuring NetBackup Client]" -ForegroundColor Cyan
	$NBUKey = "HKLM:\SOFTWARE\Veritas\NetBackup\CurrentVersion\Config"
	Write-Host "-> Setting Clientname, Browser and custom config values" -ForegroundColor Green
	Set-ItemProperty -Path $NBUKey -Name "Client_Name" -Value "$ClientName" -Type String -Force
	Set-ItemProperty -Path $NBUKey -Name "Browser" -Value "$ClientName" -Type String -Force
	Set-ItemProperty -Path $NBUKey -Name "Perform_Default_Search" -Value "NO" -Type String -Force
	Set-ItemProperty -Path $NBUKey -Name "Use_Archive_Bit" -Value "NO" -Type String -Force
	Set-ItemProperty -Path $NBUKey -Name "Buffer_Size" -Value "256" -Type DWORD -Force

	Write-Host "-> Setting unused services to Manual startup" -ForegroundColor Green
	Set-Service "NetBackup SAN Client Fibre Transport Service" -StartupType Manual -ErrorAction SilentlyContinue
	Set-Service "BMR Boot Service" -StartupType Manual -ErrorAction SilentlyContinue

	if (Test-Path "$TempDir\SITE-SERVERLIST.cmd" -ErrorAction SilentlyContinue) {
		Write-Host "-> Importing site-specific master/media server list" -ForegroundColor Green
		start-process -Wait SITE-SERVERLIST.cmd -WorkingDirectory "$TempDir" -WindowStyle Minimized
	} else {
		Write-Host "-> Warning: No Site-Specific serverlist file found!" -ForegroundColor Yellow
	}

	########################################
	## Add to Policy Section
	########################################
	if (($InstallType -eq "Reinstall") -or ($InstallType -eq "ForceReinstall")) {
		Write-Host "`n[Skipping Policy Configuration as InstallType = `'$InstallType`']" -ForegroundColor Cyan
	}

	if (($InstallType -eq "Install") -or ($InstallType -eq "ForceInstall")) {
		## Generate Data for csv policy import file
		Write-Host "`n[Adding Client to Backup Policy]" -ForegroundColor Cyan
		Write-Host "-> Generating client-specific csv import file" -ForegroundColor Green
		if ($Arch -eq "x64") { $PCType = "Windows-x64" } else { $PCType = "Windows-x86" }
		$OSType = "Windows"
		Write-Host "--> PC/OS Type: $PCType / $OSType" -ForegroundColor Green
		$CSVHeader = "Name,PCType,OSType,Backup,Technician,Virtual,Policy"
		if ($Policy) {
			$CSVDetail = "$ClientName,$PCType,$OSType,Y,$UserLogin,$Virtual,$Policy"
			Write-Host "--> Adding to custom Backup Policy: $Policy" -ForegroundColor Green
			
		} else {
			$CSVDetail = "$ClientName,$PCType,$OSType,Y,$UserLogin,$Virtual"
			Write-Host "--> Adding to default Backup Policy for Site" -ForegroundColor Green
		}
		
		## Create CSV import and upload to Master Server
		Set-Content -Path "$TempDir\$ClientName.csv" -Value $CSVHeader -Encoding Ascii -Force -ErrorAction SilentlyContinue
		Add-Content -Path "$TempDir\$ClientName.csv" -Value $CSVDetail -Encoding Ascii -ErrorAction SilentlyContinue
		
		Write-Host "--> Uploading client import file to $MasterServer" -ForegroundColor Green
		Copy-Item -Path "$TempDir\$ClientName.csv" -Destination "$NewClientsPath\" -Force -ErrorAction SilentlyContinue
		
		## Validate Copy to Master was successful
		Write-Host "---> Validating upload" -ForegroundColor Green
		if (!(Test-Path -Path "$NewClientsPath\$ClientName.csv" -ErrorAction SilentlyContinue)) {
			$InstallStatus = "Failed"
			$FailureReason = "Policy import file failed to copy to MasterServer. Please ensure client is put in a policy!"
			(Send-Results)
		}
	}

	###########################################
	## Version Check and Validation Section
	###########################################
	Write-Host "`n[Validating install and Version]" -ForegroundColor Cyan

	## Validate NetBackup Service is installed
	Write-Host "-> Checking that NBU Client Service is installed" -ForegroundColor Green
	if (!(Get-Service "NetBackup Client Service" -ErrorAction SilentlyContinue)) {
		$InstallStatus = "Failed"
		$FailureReason = "NetBackup Client Service not installed"
		(Send-Results)
	}

	## Validate Version file and check version
	Write-Host "-> Checking for version.txt file" -ForegroundColor Green
	$VersionFile = "C:\Program Files\VERITAS\NetBackup\version.txt"
	if (Test-Path $VersionFile) {
		Write-Host "--> Checking the version listed in file" -ForegroundColor Green
		$InstalledVersion = (Get-Content $VersionFile)[1].split()[2]
		$InstallStatus = "Complete"
	} else {
		$InstallStatus = "Failed"
		$FailureReason = "Warning: Version File Not Found. Please verify client was installed properly."
	}
	
	## Send Final Results and Exit
	(Send-Results)
} else {
	Write-Warning "TestRun Passed, Skipping actual installation"
}