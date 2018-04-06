param(
[string]$ServerName
)

# Define the following variable, either pass via command line or edit here
# $ServerName = 'azuappsrvd89'
# $ADGroup1 = 'ServerAdmins-SQL'
# $User = 'a538006a'

# Install Remote Server Admin Tools - AD Tools 
# Install-WindowsFeature RSAT-AD-Tools
# Check if RSAT Install, otherwise Install
$rsatAD = Get-WindowsFeature | Where {$_.Name -eq "RSAT-AD-Tools"}
if($rsatAD.Installed -eq $False){Install-WindowsFeature RSAT-AD-Tools}
#$rsatAD = Get-WindowsFeature | Where {$_.Name -eq "RSAT-AD-Tools"}
# if($rsatAD.Installed -eq $False){Install-Feature -Name RSAT-AD-Tools}

# Creates "Admins-$ServerName" group in AZUGENMILLS & adds to "RDS - Client Computers" group
$Description = "Local Administrative access to $($ServerName)"
New-ADGroup `
-Description:"$($Description)" `
-GroupCategory:"Security" `
-GroupScope:"Global" `
-Name:"Admins-$($ServerName)" `
-SamAccountName:"Admins-$($ServerName)" `
-Path:"OU=Groups,OU=Information Systems,DC=azugenmills,DC=com" `
-Server:"AZUDC1.azugenmills.com"

$ADServer = Get-ADComputer -Identity $ServerName
Add-ADGroupMember -Identity 'RDS - Client Computers' -Members $ADServer -Verbose

# Add "Admins-$ServerName" to local server Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "AZUGENMILLS\Admins-$($ServerName)"
#Add-LocalGroupMember -Group "Administrators" -Member "AZUGENMILLS\Admins-$($ServerName)", "$ADGroup1"

# Configure SCOM agent to communicate with azuscmgsp1 (assumes agent already installed via Azure Alert config)
$agent=new-object -ComObject agentconfigmanager.mgmtsvccfg
$agent.AddManagementGroup("SCOM2012","azuscmgsp1.azugenmills.com",5723)
$agent.ReloadConfiguration()

# Install Netbackup agent
\\azubkp1\MSTShared\Scripts\NBU-ClientInstall\NBU-ClientInstall.ps1 -InstallType Install

# Install Symantec client v14
& "\\azubkp1\AzuAFS-Public\SEP_Client\SEP_v14.0.3752.1000\setup.exe"
