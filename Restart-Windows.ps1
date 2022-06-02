<#
.SYNOPSIS
    Automate Windows reboots in a controlled order.
.DESCRIPTION
    This script automates Windows reboots of VMs running on VMware. The script requires a CSV file with system
    details that specify the order in which to start machines up. The script connects to the hypervisor,
    collects the state of all services set to Automatic, then shuts down the machine. After all machines have
    shut down, the script restarts the machines based on the priority specified in the CSV. The script does not
    consider a machine as running unless the services are also running.
.NOTES
    File Name  : Restart-Windows.ps1
    Author     : Dan Gill - dgill@gocloudwave.com
    Requires   : Install-PowerCLI.ps1 in the same directory.
.INPUTS
   None.
.OUTPUTS
   None.
.EXAMPLE
   PS> .\Restart-Windows.ps1
#>

$ErrorActionPreference = 'Stop'
$Settings = Get-Content "$PSScriptRoot\settings.json" -Raw | ConvertFrom-Json
$VMNames = Import-Csv -Path "$PSScriptRoot\$($Settings.CSVFileName)"
$MaxRunspaces = [Math]::Ceiling($VMNames.Count / 4)
$ADCreds = $null
$LMCreds = $null
$ScriptOutput = "$PSScriptRoot\$(Get-Date -Format FileDateUniversal)-Services.csv"
$ScriptErrors = "$PSScriptRoot\$(Get-Date -Format FileDateUniversal)-ScriptErrors.log"
$MinPowerCLI = $Settings.MinimumPowerCLIVersion
$ADTssTemplateId = $Settings.SecretTemplateLookup.ActiveDirectoryAccount
$LMTssTemplateId = $Settings.SecretTemplateLookup.LocalUserWindowsAccount
$TssUsername = "PARKPLACEINTL\$Env:USERNAME"
# Create synchronized hashtable
$Configuration = [hashtable]::Synchronized(@{})
$Configuration.Services = @()
$Configuration.ScriptErrors = @()
$Configuration.VIServer = $null

# Base path to Secret Server
$ssUri = $Settings.ssUri

# Button Values
$Buttons = @{
    'OK'                     = 0
    'OKCancel'               = 1
    'AbortRetryIngnore'      = 2
    'YesNoCancel'            = 3
    'YesNo'                  = 4
    'RetryCancel'            = 5
    'CancelTryAgainContinue' = 6
}

# Icon Values
$Icon = @{
    'Stop'        = 16
    'Question'    = 32
    'Exclamation' = 48
    'Information' = 64
}

# Return Values
$Selection = @{
    'None'      = -1
    'OK'        = 1
    'Cancel'    = 2
    'Abort'     = 3
    'Retry'     = 4
    'Ignore'    = 5
    'Yes'       = 6
    'No'        = 7
    'Try Again' = 10
    'Continue'  = 11
}

# The script needs to run on the correct domain
if ($Env:USERDNSDOMAIN -ne $Settings.DNSDomain) {
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup("You must run this script from $($Settings.DNSDomain).", 0, 'Permission denied', `
            $Buttons.OK + $Icon.Stop)

    # Exiting script
    Exit 10
}

# Determine if the local machine has the minimum version of VMWare vSphere PowerCLI installed
if (!(Get-Module -Name VMware.PowerCLI -ListAvailable) -or `
    (Get-WmiObject -Class Win32_Product -Filter "Name='VMware vSphere PowerCLI'") ) {
    # Call Install-PowerCLI.ps1
    Start-Process -FilePath 'Install-PowerCLI.ps1' -WorkingDirectory $PSScriptRoot -Verb RunAs
} elseif (( Get-Module -Name VMware.PowerCLI -ListAvailable ).Version -lt [version]$MinPowerCLI) {
    # Update PowerCLI if not at the minimum acceptable version
    try {
        Update-Module VMware.PowerCLI -Force
    } catch {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Unable to update PowerCLI to minimum required version: $MinPowerCLI", 0, 'Failed update', `
                $Buttons.OK + $Icon.Stop)

        Exit 22
    }

    # Uninstall old version of PowerCLI
    Get-InstalledModule -Name VMware.PowerCLI | ForEach-Object {
        $CurrentVersion = $PSItem.Version
        Get-InstalledModule -Name $PSItem.Name -AllVersions | Where-Object -Property Version -LT $CurrentVersion
    } | Uninstall-Module -Verbose
}

. "$PSScriptRoot\Search-TssFolders.ps1"
. "$PSScriptRoot\Get-UserCredentials.ps1"
. "$PSScriptRoot\Get-VMToolsStatus.ps1"
. "$PSScriptRoot\User-Prompts.ps1"

# Use invalid certificate action from settings.json
$null = Set-PowerCLIConfiguration -InvalidCertificateAction $Settings.InvalidCertAction -Scope Session `
    -Confirm:$false

# Connect to vCenter selected using logged on user credentials
while ($null -eq $Configuration.VIServer) { $Configuration.VIServer = Connect-VIServer $Settings.vCenter }

$VMs = Get-VM -Name $VMNames.Name -Server $Configuration.VIServer

# Get VM Tools status for all VMs
$VMsTools = Get-VMToolsStatus -InputObject $VMs
foreach ($VM in $VMsTools) {
    if ($VM.UpgradeStatus -ne 'guestToolsCurrent') {
        $Configuration.ScriptErrors += "WARNING: The version of VMware Tools on VM '$($VM.Name)' is " +
        'out of date and may cause the script to work improperly.'
        if ($VM.Status -ne 'toolsOk') {
            $Configuration.ScriptErrors += 'WARNING: VMware Tools NOT OK. Stopping VM instead of shutting down.'
        }
    }
}

# Prompt for Thycotic credentials
$ThycoticCreds = $null
$Session = $null
$ButtonClicked = $null

while (($null -eq $Session) -and ($ButtonClicked -ne $Selection.Cancel)) {
    $ThycoticCreds = Get-Credential -Message 'Please enter your Thycotic credentials.' -UserName $TssUsername

    if ($ThycoticCreds) {
        $Error.Clear()
        try {
            # Create session on TSS
            $Session = New-TssSession -SecretServer $ssUri -Credential $ThycoticCreds `
                -ErrorAction $ErrorActionPreference
        } catch {
            $wshell = New-Object -ComObject Wscript.Shell
            $ButtonClicked = $wshell.Popup("Login to $ssUri failed. Retry?", 0, 'Failed login', `
                    $Buttons.RetryCancel + $Icon.Exclamation)
        } finally {
            $Error.Clear()
        }
    }
}

if ($ButtonClicked -eq $Selection.Cancel) {
    $null = Close-TssSession -TssSession $Session
    $ADCreds = Get-Credential -Message 'User canceled Thycotic login. Please enter Domain Admin credentials.'
    $LMCreds = Get-Credential -Message 'User canceled Thycotic login. Please enter Local Machine Admin ' +
    'credentials.'
} else {
    try {
        $TssFolders = Search-TssFolders -TssSession $Session -TopLevelOnly $true -SearchText $Settings.TssFolder `
            -ErrorAction $ErrorActionPreference
    } catch {
        # Unable to find the folder specified in settings.json. Listing all top level folders.
        $TssFolders = Search-TssFolders -TssSession $Session -TopLevelOnly $true
    }

    if (($TssFolders.Count -eq 1) -or ($null -eq $TssFolders.Count)) {
        $TssFolder = $TssFolders
    } else {
        $Prompt = "Please select the Secret Folder (found $($TssFolders.Count)):"
        $TssFolderName = myDialogBox -Title 'Select a folder:' -Prompt $Prompt -Values $TssFolders.FolderName

        if ($TssFolderName) {
            $TssFolder = $TssFolders | Where-Object { $_.FolderName -eq $TssFolderName }
        } else {
            Disconnect-VIServer * -Confirm:$false
            $null = Close-TssSession -TssSession $Session
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup('User canceled folder selection. Exiting script.', 0, 'Exiting', $Buttons.OK + `
                    $Icon.Exclamation)

            Exit 1233
        }
    }

    # Obtain all matching secrets in the user specified folder
    $ADSecrets = Search-TssSecret -TssSession $Session -FolderId $TssFolder.id -SecretTemplateId $ADTssTemplateId
    $LMSecrets = Search-TssSecret -TssSession $Session -FolderId $TssFolder.id -SecretTemplateId $LMTssTemplateId

    # Select Domain Admin secret
    if ($ADSecrets) {
        $ADSecretName = myDialogBox -Title 'Select a secret' -Prompt 'Please select the Domain Admin Secret:' `
            -Values $ADSecrets.SecretName
    }

    # Select Local Admin secret
    if ($LMSecrets) {
        $Prompt = 'Please select the Local Machine Admin Secret:'
        $LMSecretName = myDialogBox -Title 'Select a secret' -Prompt $Prompt -Values $LMSecrets.SecretName
    }

    # Obtain Domain Admin credentials
    if ($null -eq $ADSecretName) {
        $ADCreds = Get-UserCredentials -Type 'AD' -Customer $TssFolder.FolderName
    } else {
        $ADCreds = Get-UserCredentials -Type 'AD' -Customer $TssFolder.FolderName -TssSession $Session `
            -TssFolder $TssFolder -TssRecords $ADSecrets -SecretName $ADSecretName
    }

    # Obtain Local Machine Admin credentials
    if ($null -eq $LMSecretName) {
        $LMCreds = Get-UserCredentials -Type 'DMZ' -Customer $TssFolder.FolderName
    } else {
        $LMCreds = Get-UserCredentials -Type 'DMZ' -Customer $TssFolder.FolderName -TssSession $Session `
            -TssFolder $TssFolder -TssRecords $LMSecrets -SecretName $LMSecretName
    }

    $null = Close-TssSession -TssSession $Session
}

# Script block to parallelize collecting VM data and shutting down the VM
$Worker = {
    [CmdletBinding()]
    param (
        # Name of the VM
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]
        $VM,

        # Credentials to use for this VM
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $VMCreds,

        # Hash table for configuration data
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Configuration
    )

    begin {
        $Error.Clear()
        $ScriptText = 'try { Get-Service -ErrorAction Stop | Where-Object { $_.StartType -eq "Automatic" -and ' +
        '$_.Status -eq "Running" } | Format-Table -Property Name -HideTableHeaders } catch { Write-Warning ' +
        '"Access denied" }'
    }

    process {
        try {
            $TestAccess = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null

            if ($TestAccess.ScriptOutput -like 'WARNING: Access denied*') {
                $Configuration.ScriptErrors += "WARNING: The credentials for $($VMcreds.Username) do not work " +
                "on $($VM.Name). If this is a one-off error, please correct the credentials on the server. If " +
                'this error repeats often, update the credentials in Thycotic.'
            } else {
                # Convert multiline string to array of strings
                try {
                    $Services = (($TestAccess.ScriptOutput).Trim()).Split("`n")
                    foreach ($Service in $Services) {
                        $Configuration.Services += New-Object PSObject `
                            -Property @{ VM = $VM.Name; ServiceName = $Service.Trim() }
                    }
                } catch [System.Management.Automation.RuntimeException] {
                    $Configuration.ScriptErrors += "WARNING: Get-Service returned NULL on $($VM.Name)."
                }

                if ($VM.ExtensionData.Guest.ToolsStatus -eq 'toolsOk') {
                    # $null = Stop-VMGuest -VM $VM -Server $Configuration.VIServer -Confirm:$false
                } else {
                    # $null = Stop-VM -VM $VM -Server $Configuration.VIServer -Confirm:$false
                }

            }
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
            $Configuration.ScriptErrors += "WARNING: The credentials for $($VMcreds.Username) do not work on " +
            "$($VM.Name). If this is a one-off error, please correct the credentials on the server. If this " +
            'error repeats often, then update the credentials in Thycotic.'
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
            $Configuration.ScriptErrors += "WARNING: Invalid argument processing $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): " +
            "$($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += "Parameters: Server - $($Configuration.VIServer), VM - $($VM.Name), " +
            "GuestCredential - $($VMcreds.Username)"
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException], `
            [System.InvalidOperationException] {
            $Configuration.ScriptErrors += "WARNING: Failure connecting to $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): " +
            "$($_.InvocationInfo.Line)"
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
            $Configuration.ScriptErrors += "WARNING: Unable to process $($VM.Name). Check the VM to ensure it " +
            'is working properly. Error message and attempted command below:'
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): " +
            "$($_.InvocationInfo.Line)"
        } catch {
            $Configuration.ScriptErrors += "WARNING: Other error processing $($VM.Name)."
            $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): " +
            "$($_.InvocationInfo.Line)"
        } finally {
            $Error.Clear()
        }
    }
}

# Create runspace pool for parralelization
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
$RunspacePool.Open()

$Jobs = New-Object System.Collections.ArrayList

# Display progress bar
Write-Progress -Id 1 -Activity 'Creating Runspaces' -Status "Creating runspaces for $($VMsTools.Count) VMs." `
    -PercentComplete 0

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$VMindex = 1
# Create job for each VM
foreach ($VM in $VMs) {
    if ($VM.Guest.HostName -notlike '*.*') {
        $Creds = $LMCreds
    } else {
        $Creds = $ADCreds
    }

    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $null = $PowerShell.AddScript($Worker).AddArgument($VM).AddArgument($Creds).AddArgument($Configuration)

    $JobObj = New-Object -TypeName PSObject -Property @{
        Runspace   = $PowerShell.BeginInvoke()
        PowerShell = $PowerShell
    }

    $null = $Jobs.Add($JobObj)
    $RSPercentComplete = ($VMindex / $VMs.Count ).ToString('P')
    $Activity = "Runspace creation: Processing $VM"
    $Status = "$VMindex/$($VMs.Count) : $RSPercentComplete Complete"
    Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $RSPercentComplete.Replace('%', '')

    $VMindex++
}

Write-Progress -Id 1 -Activity 'Runspace creation' -Completed

# Used to determine percentage completed.
$TotalJobs = $Jobs.Runspace.Count

Write-Progress -Id 2 -Activity 'Collect services' -Status 'Collecting services.' -PercentComplete 0

# Update percentage complete and wait until all jobs are finished.
while ($Jobs.Runspace.IsCompleted -contains $false) {
    $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
    $PercentComplete = ($CompletedJobs / $TotalJobs ).ToString('P')
    $Status = "$CompletedJobs/$TotalJobs : $PercentComplete Complete"
    Write-Progress -Id 2 -Activity 'Collect services' -Status $Status `
        -PercentComplete $PercentComplete.Replace('%', '')
    Start-Sleep -Milliseconds 100
}

# Clean up runspace.
$RunspacePool.Close()

Write-Progress -Id 2 -Activity 'Collect services' -Completed
<#
$VMs = Get-VM -Name $VMNames.Name -Server $Configuration.VIServer
$VMCount = $VMs.Count

Write-Progress -Id 2 -Activity 'Shutdown' -Status 'Waiting for shutdown.' -PercentComplete 0

while ($VMs.PowerState -contains 'PoweredOn') {
    $VMsShutdown = ($VMs.PowerState -eq 'PoweredOff').Count
    $PercentComplete = ($VMsShutdown / $VMCount).ToString('P')
    $Status = "$VMsShutdown/$VMCount : $PercentComplete Complete"
    Write-Progress -Id 2 -Activity 'Shutdown' -Status $Status `
        -PercentComplete $PercentComplete.Replace('%', '')
    Start-Sleep -Milliseconds 1000
    $VMs = Get-VM -Name $VMNames.Name -Server $Configuration.VIServer
}

Write-Progress -Id 2 -Activity 'Shutdown' -Completed
 #>
# Disconnect from vCenter
Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false

# Write script output to log file
if (Test-Path -Path $ScriptOutput -PathType leaf) { Clear-Content -Path $ScriptOutput }
$Configuration.Services | Export-Csv -Path $ScriptOutput -NoTypeInformation -Force

# Write script errors to log file
if (Test-Path -Path $ScriptErrors -PathType leaf) { Clear-Content -Path $ScriptErrors }
Add-Content -Path $ScriptErrors -Value $Configuration.ScriptErrors

Write-Host "Script log saved to $ScriptOutput"
Write-Host "Script error log saved to $ScriptErrors"

$wshell = New-Object -ComObject Wscript.Shell
$elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
$null = $wshell.Popup("Operation Completed in $elapsedMinutes minutes", 0, 'Done', $Buttons.OK + $Icon.Information)
#####END OF SCRIPT#######