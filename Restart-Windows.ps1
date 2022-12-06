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

# Create synchronized hashtable
$Configuration = [hashtable]::Synchronized(@{})
$Configuration.Services = @()
$Configuration.ScriptErrors = @()
$Configuration.Shutdown = @{}
$Configuration.VIServer = $null
$Configuration.CredsTest = @{}

$ButtonClicked = $null
$ADCreds = $null
$LMCreds = $null
$ADSecrets = $null
$LMSecrets = $null
$VMCreds = @{}

# Prompt user for JSON file with settings
[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null

$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.initialDirectory = $PSScriptRoot
$OpenFileDialog.title = 'Select JSON file with customer settings'
$OpenFileDialog.filter = 'JavaScript Object Notation files (*.json)|*.json'
if ($OpenFileDialog.ShowDialog() -eq 'Cancel') {
    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup('User canceled file selection. Exiting script.', 0, 'Exiting', `
            $Buttons.OK + $Icon.Exclamation)

    Exit 1223
}

$Settings = Get-Content "$($OpenFileDialog.filename)" -Raw | ConvertFrom-Json
$Configuration.SvcWhitelist = $Settings.SvcWhitelist

# Display settings details and ask user to confirm continuation of script
if ($Settings.vCenterRP) {
    $wshell = New-Object -ComObject Wscript.Shell
    $ButtonClicked = $wshell.Popup("Do you want to process customer $($Settings.vCenterRP) using Thycotic folder " +
        "$($Settings.TssFolder)?", 0, 'Confirm customer', $Buttons.YesNo + $Icon.Question)
}

# Exit script if Customer field empty or if user selected no.
if ($null -eq $ButtonClicked -or $ButtonClicked -eq $Selection.No) { Exit 1223 }

# Prompt user for CSV with VMs, Process, BootGroup, and (optionally) ShutdownGroup
[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null

$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.initialDirectory = $PSScriptRoot
$OpenFileDialog.title = 'Select CSV file with VM names and processing order'
$OpenFileDialog.filter = 'Comma-delimited files (*.csv)|*.csv'
if ($OpenFileDialog.ShowDialog() -eq 'Cancel') {
    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup('User canceled file selection. Exiting script.', 0, 'Exiting', `
            $Buttons.OK + $Icon.Exclamation)

    Exit 1223
}

$VMTable = Import-Csv -Path "$($OpenFileDialog.filename)"

# Exit script if required fields are not present
if (![bool]($VMTable | Get-Member -Name Name) -or ![bool]($VMTable | Get-Member -Name Process) `
        -or ![bool]($VMTable | Get-Member -Name BootGroup)) {
    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup('CSV malformed, please review requirements and correct. Exiting script.', 0, 'Exiting', `
            $Buttons.OK + $Icon.Exclamation)

    Exit 11
}

# Check for ShutdownGroup column, if it doesn't exist shutdown order doesn't matter set all to 1
if (![bool]($VMTable | Get-Member -Name ShutdownGroup)) {
    $VMTable | Add-Member -MemberType NoteProperty -Name 'ShutdownGroup' -Value '1'
}

# Check for Stage column, if it doesn't exist only one stage exists
if (![bool]($VMTable | Get-Member -Name Stage)) {
    $VMTable | Add-Member -MemberType NoteProperty -Name 'Stage' -Value '1'
}

# Correct null values in groups by replacing with 1 or false
foreach ($VM in $VMTable) {
    $VM.Process = [System.Convert]::ToBoolean($VM.Process)
    if ($null -eq $VM.Process) {
        $VM.Process = $false
    }

    if ($null -eq $VM.BootGroup) {
        $VM.BootGroup = 1
    }

    if ($null -eq $VM.ShutdownGroup) {
        $VM.ShutdownGroup = 1
    }

    if ($null -eq $VM.Stage) {
        $VM.Stage = 1
    }
}

# Drop all rows that the script shouldn't process
$VMTable = $VMTable | Where-Object { $_.Process -ceq $true }

$Stages = $VMTable.Stage | Sort-Object -Unique -CaseSensitive
$TotalStages = $Stages.Count
if ($null -eq $TotalStages) { $TotalStages = 1 }

# Prompt user for location of output files
Add-Type -AssemblyName System.Windows.Forms
$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$FolderBrowser.Description = 'Select a folder in which to store logs and temporary files.'
[void]$FolderBrowser.ShowDialog()

$ScriptOutput = "$($FolderBrowser.SelectedPath)\$(Get-Date -Format FileDateUniversal)-Services.csv"
$ScriptErrors = "$($FolderBrowser.SelectedPath)\$(Get-Date -Format FileDateUniversal)-ScriptErrors.log"
$ADTssTemplateId = $Settings.SecretTemplateLookup.ActiveDirectoryAccount
$LMTssTemplateId = $Settings.SecretTemplateLookup.LocalUserWindowsAccount
$TssUsername = "$($Settings.TssDomain)\$($Settings.TssUser)"

# Base path to Secret Server
$ssUri = $Settings.ssUri

# The script needs to run on the correct domain
if ($Env:USERDNSDOMAIN -ne $Settings.DNSDomain) {
    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup("You must run this script from $($Settings.DNSDomain).", 0, 'Permission denied', `
            $Buttons.OK + $Icon.Stop)

    # Exiting script
    Exit 10
}

. "$PSScriptRoot\Search-TssFolders.ps1"
. "$PSScriptRoot\Get-UserCredentials.ps1"
. "$PSScriptRoot\Get-VMToolsStatus.ps1"
. "$PSScriptRoot\User-Prompts.ps1"

# Install or update to latest PowerCLI version
$PowerCLIPSModule = Get-Module -Name VMware.PowerCLI -ListAvailable
$PowerCLIAllPrograms = Get-Package -ProviderName Programs -IncludeWindowsInstaller | `
    Where-Object { $_.Name -eq 'VMware vSphere PowerCLI' }

if ($null -eq $PowerCLIPSModule -or $PowerCLIAllPrograms) {
    # Call Install-PowerCLI
    Start-Process -FilePath powershell.exe `
        -ArgumentList { . "$PSScriptRoot\Install-PowerCLI.ps1"; Install-PowerCLI } -Verb RunAs -Wait
} elseif ($PowerCLIPSModule.Version -lt (Find-Module -Name VMware.PowerCLI).Version) {
    # Update PowerCLI if not at the latest version
    try {
        Start-Process -FilePath powershell.exe -ArgumentList {
            try {
                Update-Module -Name VMware.PowerCLI -Force -ErrorAction Stop
            } catch {
                Install-Module -Name VMware.PowerCLI -SkipPublisherCheck -Force
            }
        } -Verb RunAs -Wait
    } catch {
        $wshell = New-Object -ComObject Wscript.Shell
        $null = $wshell.Popup('Unable to update PowerCLI to latest version.', 0, 'Failed update', `
                $Buttons.OK + $Icon.Stop)

        Exit 10
    }

    # Uninstall old versions of PowerCLI
    Start-Process -FilePath powershell.exe -ArgumentList {
        Get-InstalledModule -Name VMware.PowerCLI | ForEach-Object {
            $CurrVersion = $PSItem.Version
            Get-InstalledModule -Name $PSItem.Name -AllVersions | Where-Object -Property Version -LT $CurrVersion
        } | Uninstall-Module -Verbose
    } -Verb RunAs -Wait
}

# Install or update to latest Thycotic.SecretServer PowerShell module
$TssPSModule = Get-Module -Name Thycotic.SecretServer -ListAvailable

if ($null -eq $TssPSModule) {
    if ((Get-PSRepository -Name 'PSGallery').InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    }
    Start-Process -FilePath powershell.exe -ArgumentList {
        Install-Module -Name Thycotic.SecretServer -Confirm:$false -AllowClobber -Force
    } -Verb RunAs -Wait
} elseif ($TssPSModule.Version -lt (Find-Module -Name Thycotic.SecretServer).Version) {
    Start-Process -FilePath powershell.exe -ArgumentList { Update-Module -Name Thycotic.SecretServer -Force } `
        -Verb RunAs -Wait

    # Uninstall old versions of Thycotic.SecretServer
    Start-Process -FilePath powershell.exe -ArgumentList {
        Get-InstalledModule -Name Thycotic.SecretServer | ForEach-Object {
            $CurrVersion = $PSItem.Version
            Get-InstalledModule -Name $PSItem.Name -AllVersions | Where-Object -Property Version -LT $CurrVersion
        } | Uninstall-Module -Verbose
    } -Verb RunAs -Wait
}

function Wait-Stage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        [string[]] $Action,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullorEmpty()]
        [string[]] $Message
    )

    begin {
        $SleepSeconds = $Settings.MinsBtwStages * 60
    }

    process {
        switch ($Action) {
            'Time' { Write-Host $Message; Start-Sleep -Seconds $SleepSeconds }
            Default { Write-Host 'No action specified.' }
        }
    }

    end {

    }
}

# Use invalid certificate action from settings.json
$null = Set-PowerCLIConfiguration -InvalidCertificateAction $Settings.InvalidCertAction -Scope Session `
    -Confirm:$false

# Connect to vCenter using logged on user credentials
while ($null -eq $Configuration.VIServer) { $Configuration.VIServer = Connect-VIServer $Settings.vCenter }

try {
    $VMs = Get-VM -Name $VMTable.Name -Server $Configuration.VIServer
} catch {
    # Disconnect from vCenter
    Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false
    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup("A VM is in the CSV that doesn't exist on the vCenter server. Please check the CSV.",
        0, 'Exiting', $Buttons.OK + $Icon.Exclamation)

    Exit 1223
}


# Get VM Tools status for all VMs
$VMsTools = Get-VMToolsStatus -InputObject $VMs
foreach ($VM in $VMsTools) {
    if ($VM.UpgradeStatus -ne 'guestToolsCurrent') {
        $msg = ("$(Get-Date -Format G): WARNING: The version of VMware Tools on VM '$($VM.Name)' is out of " +
            'date and may cause the script to work improperly.')
        $Configuration.ScriptErrors += $msg
        if ($VM.Status -ne 'toolsOk') {
            $msg = ("$(Get-Date -Format G): WARNING: VMware Tools NOT OK on '$($VM.Name)'. Stopping VM " +
                'instead of shutting down.')
            $Configuration.ScriptErrors += $msg
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
    if ($Session) { $null = Close-TssSession -TssSession $Session }
    $ADCreds = Get-Credential -Message 'Please enter Domain Admin credentials.'
    $LMCreds = Get-Credential -Message 'Please enter Local Machine Admin credentials.'
} else {
    try {
        $TssFolders = Search-TssFolders -TssSession $Session -TopLevelOnly $false -SearchText $Settings.TssFolder `
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
            $null = $wshell.Popup('User canceled folder selection. Exiting script.', 0, 'Exiting', $Buttons.OK + `
                    $Icon.Exclamation)

            Exit 1223
        }
    }

    # Obtain all matching secrets in the user specified folder
    try {
        $ADSecrets = Search-TssSecret -TssSession $Session -FolderId $TssFolder.id `
            -SecretTemplateId $ADTssTemplateId -ErrorAction $ErrorActionPreference
        $LMSecrets = Search-TssSecret -TssSession $Session -FolderId $TssFolder.id `
            -SecretTemplateId $LMTssTemplateId -ErrorAction $ErrorActionPreference
    } catch {
        $Configuration.ScriptErrors += 'WARNING: Thycotic API failure occured. Prompting user for credentials.'
    }

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
        $ADCreds = Get-UserCredentials -Type 'AD Administrator' -Customer $Settings.vCenterRP
    } else {
        $ADCreds = Get-UserCredentials -Type 'AD Administrator' -Customer $Settings.vCenterRP -TssSession $Session `
            -TssFolder $TssFolder -TssRecords $ADSecrets -SecretName $ADSecretName
    }

    # Obtain Local Machine Admin credentials
    if ($null -eq $LMSecretName) {
        $LMCreds = Get-UserCredentials -Type 'Local Machine' -Customer $Settings.vCenterRP
    } else {
        $LMCreds = Get-UserCredentials -Type 'Local Machine' -Customer $Settings.vCenterRP -TssSession $Session `
            -TssFolder $TssFolder -TssRecords $LMSecrets -SecretName $LMSecretName
    }

    $null = Close-TssSession -TssSession $Session
}

# Script block to parallelize testing credentials
$TestCredentials = {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullorEmpty()]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine] $VM,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential] $VMcreds,
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullorEmpty()]
        $Configuration
    )

    $Error.Clear()
    try {
        $ScriptText = ('try { Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop } ' +
            "catch { Write-Warning 'Access denied' }")
        $TestAccess = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
            -GuestCredential $VMcreds -ErrorAction Stop 3> $null

        if ($TestAccess.ScriptOutput -like 'WARNING: Access denied*') {
            $Configuration.CredsTest[$VM.Name] = 'FAIL'
        } else {
            $Configuration.CredsTest[$VM.Name] = 'SUCCESS'
        }
    } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
        $Configuration.CredsTest[$VM.Name] = 'FAIL'
    } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
        $line = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
        $params = ("Parameters: Server - $($Configuration.VIServer), VM - $VM, GuestCredential - " +
            "$($VMcreds.Username)")
        $Configuration.ScriptErrors += "WARNING: Invalid argument processing $VM."
        $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
        $Configuration.ScriptErrors += $line
        $Configuration.ScriptErrors += $params
        $Configuration.CredsTest[$VM.Name] = 'FAIL'
    } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException],
    [System.InvalidOperationException],
    [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
        $line = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
        $Configuration.ScriptErrors += "WARNING: Failure connecting to $VM."
        $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
        $Configuration.ScriptErrors += $line
        $Configuration.CredsTest[$VM.Name] = 'FAIL'
    } catch {
        $Configuration.ScriptErrors += "WARNING: Other error processing $VM."
        $line = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
        $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
        $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
        $Configuration.ScriptErrors += $line
        $Configuration.CredsTest[$VM.Name] = 'FAIL'
    } finally {
        $Error.Clear()
    }

}

$VMTestGroup = $VMs | Where-Object { $_.Guest.HostName -notlike '*.*' }
if ($VMTestGroup) {
    <# Action to perform if the condition is true #>
    $VMTestGroup += $VMs | Where-Object { $_.Guest.HostName -like '*.*' } | Get-Random

} else {
    <# Action when all if and elseif conditions are false #>
    $VMTestGroup = $VMs | Where-Object { $_.Guest.HostName -like '*.*' } | Get-Random
}
$VMTestCount = $VMTestGroup.Count

# Process no more than 25% of the list at once. (Minimum value = 20)
$MaxRunspaces = [Math]::Max([Math]::Ceiling($VMTestCount / 4), 20)

# Create runspace pool for parralelization
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
$RunspacePool.Open()

$Jobs = New-Object System.Collections.ArrayList

# Display progress bar
Write-Progress -Id 1 -Activity 'Creating Runspaces to test credentials' `
    -Status "Creating runspaces for $VMTestCount VMs." -PercentComplete 0

$VMindex = 1
# Create job for each VM

foreach ($VM in $VMTestGroup) {
    <# $VM is the current item #>
    if ($VM.Guest.HostName -notlike '*.*') {
        $Creds = $LMCreds
    } else {
        $Creds = $ADCreds
    }

    $PowerShell = [powershell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $null = $PowerShell.AddScript($TestCredentials).AddArgument($VM).AddArgument($Creds).AddArgument($Configuration)

    $JobObj = New-Object -TypeName PSObject -Property @{
        Runspace   = $PowerShell.BeginInvoke()
        PowerShell = $PowerShell
    }

    $null = $Jobs.Add($JobObj)
    $RSPercentComplete = ($VMindex / $VMTestCount).ToString('P')
    $Activity = "Runspace creation: Processing $VM"
    $Status = "$VMindex/$VMTestCount : $RSPercentComplete Complete"
    $CleanPercent = $RSPercentComplete.Replace('%', '')
    Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $CleanPercent

    $VMindex++
}

Write-Progress -Id 1 -Activity 'Runspace creation to test credentials' -Completed

# Used to determine percentage completed.
$TotalJobs = $Jobs.Runspace.Count

Write-Progress -Id 2 -Activity 'Testing credentials' -Status 'Verifying credentials' `
    -PercentComplete 0

# Update percentage complete and wait until all jobs are finished.
while ($Jobs.Runspace.IsCompleted -contains $false) {
    $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
    $PercentComplete = ($CompletedJobs / $TotalJobs).ToString('P')
    $Status = "$CompletedJobs/$TotalJobs : $PercentComplete Complete"
    Write-Progress -Id 2 -Activity 'Testing credentials' -Status $Status `
        -PercentComplete $PercentComplete.Replace('%', '')
    Start-Sleep -Milliseconds 100
}

# Clean up runspace.
$RunspacePool.Close()

Write-Progress -Id 2 -Activity 'Testing credentials' -Completed

if ($Configuration.CredsTest.ContainsValue('FAIL')) {
    <# Clean up and exit script #>
    # Disconnect from vCenter
    Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false

    $FailedLogins = $Configuration.CredsTest.GetEnumerator() | Where-Object { $_.Value -eq 'FAIL' }

    # Write script errors to log file
    if (Test-Path -Path $ScriptErrors -PathType leaf) { Clear-Content -Path $ScriptErrors }
    Add-Content -Path $ScriptErrors -Value $Configuration.ScriptErrors

    Write-Host "$(Get-Date -Format G): Script error log saved to $ScriptErrors"

    $wshell = New-Object -ComObject Wscript.Shell
    $null = $wshell.Popup("Login failed for one or more servers: $($FailedLogins.Key)", 0, 'Login failed', `
            $Buttons.OK + $Icon.Exclamation)

    Exit 5
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$VMTable = $VMTable | Sort-Object -Property Stage -CaseSensitive
$StageIdx = 1

foreach ($Stage in $Stages) {
    <# $Stage is the current item #>
    Write-Host "Starting stage $Stage."
    $StageTable = $VMTable | Where-Object { $_.Stage -ceq $Stage }
    $StageCount = $StageTable.Count
    if ($null -eq $StageCount) { $StageCount = 1 }
    $BootGroups = $StageTable.BootGroup | Sort-Object -Unique -CaseSensitive
    $ShutdownGroups = $StageTable.ShutdownGroup | Sort-Object -Unique -CaseSensitive

    # Script block to parallelize collecting VM data and shutting down the VM
    $ShutdownWorker = {
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
            $ErrorActionPreference = 'Stop'
            $Error.Clear()
            $SvcWhitelist = "'$($($Configuration.SvcWhitelist) -join "','")'"

            $ScriptText = ("try { Get-Service -Include $SvcWhitelist -ErrorAction Stop | Where-Object { " +
                '$_.StartType -eq "Automatic" -and $_.Status -eq "Running" } | Format-Table -Property Name ' +
                '-HideTableHeaders } catch { Write-Warning "Access denied" }')
        }

        process {
            try {
                Write-Host "$(Get-Date -Format G): INFO: Attempting service collection on $($VM.Name)."
                $CollectedServices = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                    -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null

                if ($CollectedServices.ScriptOutput -like 'WARNING: Access denied*') {
                    $ErrorMessage = ("$(Get-Date -Format G): SHUTDOWN WARNING: The credentials for " +
                        "$($VMcreds.Username) do not work on $($VM.Name). If this is a one-off error, please correct " +
                        'the credentials on the server. If this error repeats often, update the credentials in ' +
                        'Thycotic. Service collection failed.')
                    $Configuration.ScriptErrors += $ErrorMessage
                    $Configuration.Shutdown[$VM.Name] = $false
                } else {
                    # Convert multiline string to array of strings
                    try {
                        $Services = (($CollectedServices.ScriptOutput).Trim()).Split("`n")
                        foreach ($Service in $Services) {
                            if ($Service.Trim()) {
                                <# Do no output if service list is empty #>
                                $Configuration.Services += New-Object PSObject `
                                    -Property @{ VM = $VM.Name; ServiceName = $Service.Trim() }
                            }
                        }
                        Write-Host "$(Get-Date -Format G): Collected services for $($VM.Name)."
                    } catch [System.Management.Automation.RuntimeException] {
                        $msg = ("$(Get-Date -Format G): SHUTDOWN WARNING: Get-Service returned NULL on $($VM.Name)." +
                            ' Retrying.')
                        Write-Host $msg -BackgroundColor Black -ForegroundColor Yellow
                        $CollectedServices = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText `
                            $ScriptText -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null

                        if ($CollectedServices.ScriptOutput -like 'WARNING: Access denied*') {
                            $ErrorMessage = ("$(Get-Date -Format G): SHUTDOWN WARNING: The credentials for " +
                                "$($VMcreds.Username) do not work on $($VM.Name). If this is a one-off error, please " +
                                'correct the credentials on the server. If this error repeats often, update the ' +
                                'credentials in Thycotic. Service collection failed.')
                            $Configuration.ScriptErrors += $ErrorMessage
                            $Configuration.Shutdown[$VM.Name] = $false
                        } else {
                            # Convert multiline string to array of strings
                            try {
                                $Services = (($CollectedServices.ScriptOutput).Trim()).Split("`n")
                                foreach ($Service in $Services) {
                                    $Configuration.Services += New-Object PSObject `
                                        -Property @{ VM = $VM.Name; ServiceName = $Service.Trim() }
                                }
                                Write-Host "$(Get-Date -Format G): Collected services for $($VM.Name)."
                            } catch [System.Management.Automation.RuntimeException] {
                                $msg = ("$(Get-Date -Format G): SHUTDOWN WARNING: Get-Service returned NULL on " +
                                    "$($VM.Name). This is the second time all Automatic services were running. " +
                                    'Script will only exclude the Excluded Services list from boot check.')
                                $Configuration.ScriptErrors += $msg
                                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                            }
                        }
                    }

                    if ($VM.ExtensionData.Guest.ToolsStatus -eq 'toolsOk') {
                        Write-Host "$(Get-Date -Format G): Shutting down $($VM.Name)."
                        $null = Stop-VMGuest -VM $VM -Server $Configuration.VIServer -Confirm:$false
                    } else {
                        Write-Host "$(Get-Date -Format G): Stopping $($VM.Name)."
                        $null = Stop-VM -VM $VM -Server $Configuration.VIServer -Confirm:$false
                    }
                    $Configuration.Shutdown[$VM.Name] = $true

                }
            } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
                $ErrorMessage = ("$(Get-Date -Format G): SHUTDOWN WARNING: The credentials for $($VMcreds.Username) " +
                    "do not work on $($VM.Name). If this is a one-off error, please correct the credentials on the " +
                    'server. If this error repeats often, then update the credentials in Thycotic.')
                Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
                $msg = "$(Get-Date -Format G): SHUTDOWN WARNING: Invalid argument processing $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
                $ErrorMessage = ("Parameters: Server - $($Configuration.VIServer), VM - $($VM.Name), " +
                    "GuestCredential - $($VMcreds.Username)")
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException], `
                [System.InvalidOperationException] {
                $msg = "$(Get-Date -Format G): SHUTDOWN WARNING: Failure connecting to $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
                $ErrorMessage = ("$(Get-Date -Format G): SHUTDOWN WARNING: Unable to process $($VM.Name). Check the " +
                    'VM to ensure it is working properly. Error message and attempted command below:')
                Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } catch {
                $msg = "$(Get-Date -Format G): SHUTDOWN WARNING: Other error processing $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } finally {
                $Error.Clear()
            }
        }
    }

    $StageTable = $StageTable | Sort-Object -Property ShutdownGroup, Name -CaseSensitive

    foreach ($group in $ShutdownGroups) {
        $GroupMembers = $StageTable | Where-Object { $_.ShutdownGroup -ceq $group }
        $GroupCount = $GroupMembers.Count
        if ($null -eq $GroupCount) { $GroupCount = 1 }
        $VMGroup = $VMs | Where-Object { $GroupMembers.Name -eq $_.Name }

        # Process no more than 25% of the list at once. (Minimum value = 20)
        $MaxRunspaces = [Math]::Max([Math]::Ceiling($GroupCount / 4), 20)

        # Create runspace pool for parralelization
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
        $RunspacePool.Open()

        $Jobs = New-Object System.Collections.ArrayList

        # Display progress bar
        Write-Progress -Id 1 -Activity "Creating Runspaces for stage $Stage, group $group" `
            -Status "Creating runspaces for $GroupCount VMs." -PercentComplete 0

        $VMindex = 1
        # Create job for each VM
        foreach ($VM in $VMGroup) {
            if ($VM.Guest.HostName -notlike '*.*') {
                $Creds = $LMCreds
            } else {
                $Creds = $ADCreds
            }

            # Saving credentials to hashtable because HostName sometimes changes after shutdown.
            $VMCreds[$VM.Name] = $Creds

            $PowerShell = [powershell]::Create()
            $PowerShell.RunspacePool = $RunspacePool
            $null = $PowerShell.AddScript($ShutdownWorker).AddArgument($VM).AddArgument($Creds).AddArgument($Configuration)

            $JobObj = New-Object -TypeName PSObject -Property @{
                Runspace   = $PowerShell.BeginInvoke()
                PowerShell = $PowerShell
            }

            $null = $Jobs.Add($JobObj)
            $RSPercentComplete = ($VMindex / $GroupCount).ToString('P')
            $Activity = "Runspace creation: Processing $VM, Stage $Stage, Group $group"
            $Status = "$VMindex/$GroupCount : $RSPercentComplete Complete"
            $CleanPercent = $RSPercentComplete.Replace('%', '')
            Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $CleanPercent

            $VMindex++
        }

        Write-Progress -Id 1 -Activity "Runspace creation for stage $Stage, group $group" -Completed

        # Used to determine percentage completed.
        $TotalJobs = $Jobs.Runspace.Count

        Write-Progress -Id 2 -Activity "Processing shutdown; Stage $Stage, Group $group" -Status 'Shutting down.' `
            -PercentComplete 0

        # Update percentage complete and wait until all jobs are finished.
        while ($Jobs.Runspace.IsCompleted -contains $false) {
            $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
            $PercentComplete = ($CompletedJobs / $TotalJobs).ToString('P')
            $Status = "Shutting down. $CompletedJobs/$TotalJobs : $PercentComplete Complete"
            Write-Progress -Id 2 -Activity "Collecting services and shutting down; Stage $stage, Group $group" `
                -Status $Status -PercentComplete $PercentComplete.Replace('%', '')
            Start-Sleep -Milliseconds 100
        }

        # Clean up runspace.
        $RunspacePool.Close()

        Write-Progress -Id 2 -Activity "Processing shutdown; Stage $Stage, Group $group" -Completed

        Write-Progress -Id 2 -Activity 'Shutdown' -Status 'Waiting for shutdown.' -PercentComplete 0

        $ShutdownList = ($Configuration.Shutdown.GetEnumerator() | Where-Object { $_.Value -eq 'True' }).key | `
            Where-Object { $GroupMembers.Name -eq $_ }
        $VMGroup = Get-VM -Name $ShutdownList -Server $Configuration.VIServer
        $GroupCount = $VMGroup.Count

        while ($VMGroup.PowerState -contains 'PoweredOn') {
            $VMsShutdown = ($VMGroup.PowerState -eq 'PoweredOff').Count
            $PercentComplete = ($VMsShutdown / $GroupCount).ToString('P')
            $Status = "Waiting for shutdown. $VMsShutdown/$GroupCount : $PercentComplete Complete"
            Write-Progress -Id 2 -Activity 'Shutdown' -Status $Status `
                -PercentComplete $PercentComplete.Replace('%', '')
            $PoweredOnVMs = $VMGroup | Where-Object { $_.PowerState -eq 'PoweredOn' }
            Write-Host "$(Get-Date -Format G): Waiting for the following machines to shut down: $PoweredOnVMs" `
                -BackgroundColor Yellow -ForegroundColor DarkRed
            Start-Sleep -Milliseconds 1000
            $VMGroup = Get-VM -Name $ShutdownList -Server $Configuration.VIServer
        }

        Write-Progress -Id 2 -Activity 'Shutdown' -Completed
    }

    # Write services data to CSV. If manual intervention is needed, user can access this file to check services.
    if (Test-Path -Path $ScriptOutput -PathType leaf) { Clear-Content -Path $ScriptOutput }
    $Configuration.Services | Export-Csv -Path $ScriptOutput -NoTypeInformation -Force

    Write-Host "$(Get-Date -Format G): Services list saved to $ScriptOutput"

    # Script block to parallelize booting VMs
    $BootWorker = {
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
            $ErrorActionPreference = 'Stop'
            $Error.Clear()
            # Run two Powershell commands with one Invoke-VMScript.
            # Get service status for all services in ServicesList and use while loop to wait until all services are
            # running.
            if ($Configuration.Services | Where-Object { $_.VM -eq $VM.Name }) {
                $ServerServices = ($Configuration.Services | Where-Object { $_.VM -eq $VM.Name }).ServiceName
            }

            $ServiceList = "'$($ServerServices -join "','")'"
            $ScriptText = ('$Services = ' + "$ServiceList; try { while (Get-Service -Include " + '$Services | ' +
                'Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | Format-Table -Property' +
                ' Name -HideTableHeaders ) { Start-Sleep -Seconds 1 } } catch { Write-Warning "Access denied" }')

            # Wait 60 seconds so VM has time to obtain DNS HostName
            Start-Sleep -Seconds 60
        }

        process {
            try {
                # Wait for VM power state ON and DNS Name assignment
                while (($VM.PowerState -ne 'PoweredOn') -or (![bool]$VM.Guest.HostName)) {
                    $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                    # Give the machine time before attempting login after boot up
                    Write-Host "$(Get-Date -Format G): $($VM.Name) does not have a DNS name yet. Waiting 30 seconds."
                    Start-Sleep -Seconds 30
                }

                # Run script to check services.
                if ($ServerServices) {
                    $msg = "$(Get-Date -Format G): Checking the following Automatic and Running services on " + `
                        "$($VM.Name): ($ServiceList)"
                    Write-Host $msg -BackgroundColor DarkGreen -ForegroundColor Green
                    $ServicesCheck = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                        -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null

                    while ($ServicesCheck.ScriptOutput -like 'WARNING: Access denied*') {
                        Write-Host "$(Get-Date -Format G): $($VM.Name) failed login. Waiting 60s and trying again." `
                            -BackgroundColor Yellow -ForegroundColor DarkRed
                        Start-Sleep -Seconds 60

                        # Run script to check services.
                        $ServicesCheck = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                            -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null
                    }

                    Write-Host "$(Get-Date -Format G): Finished checking services on $($VM.Name)."
                } else {
                    $msg = ("$(Get-Date -Format G): $($VM.Name) had no services matching the whitelist during " +
                        'shutdown. Script will only check that the server is powered on before continuing.')
                    Write-Host $msg -BackgroundColor DarkGreen -ForegroundColor Green
                }

            } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
                $ErrorMessage = ("$(Get-Date -Format G): BOOT WARNING: The credentials for $($VMcreds.Username) do " +
                    "not work on $($VM.Name). If this is a one-off error, please correct the credentials on the " +
                    'server. If this error repeats often, then update the credentials in Thycotic.')
                Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $ErrorMessage
            } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
                $msg = "$(Get-Date -Format G): BOOT WARNING: Invalid argument processing $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
                $ErrorMessage = ("Parameters: Server - $($Configuration.VIServer), VM - $($VM.Name), " +
                    "GuestCredential - $($VMcreds.Username)")
                $Configuration.ScriptErrors += $ErrorMessage
            } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException], `
                [System.InvalidOperationException] {
                $msg = "$(Get-Date -Format G): BOOT WARNING: Failure connecting to $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
            } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
                $ErrorMessage = ("$(Get-Date -Format G): BOOT WARNING: Unable to process $($VM.Name). Check the VM " +
                    'to ensure it is working properly. Error message and attempted command below:')
                Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
            } catch {
                $msg = "$(Get-Date -Format G): BOOT WARNING: Other error processing $($VM.Name)."
                Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
                $Configuration.ScriptErrors += $msg
                $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
                $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
                $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
                $Configuration.ScriptErrors += $ErrorMessage
            } finally {
                $Error.Clear()
            }
        }
    }

    $StageTable = $StageTable | Sort-Object -Property BootGroup, Name -CaseSensitive

    foreach ($group in $BootGroups) {
        $GroupMembers = $StageTable | Where-Object { $_.BootGroup -ceq $group }
        $GroupCount = $GroupMembers.Count
        if ($null -eq $GroupCount) { $GroupCount = 1 }
        $VMGroup = $VMs | Where-Object { $GroupMembers.Name -eq $_.Name }

        # Process no more than 25% of the list at once. (Minimum value = 20)
        $MaxRunspaces = [Math]::Max([Math]::Ceiling($GroupCount / 4), 20)

        # Create runspace pool for parralelization
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
        $RunspacePool.Open()

        $Jobs = New-Object System.Collections.ArrayList

        # Display progress bar
        Write-Progress -Id 1 -Activity "Creating Runspaces for stage $Stage, group $group" `
            -Status "Creating runspaces for $GroupCount VMs." -PercentComplete 0

        $VMIdx = 1
        # Create job for each VM
        foreach ($VM in $VMGroup) {
            if ($Configuration.Shutdown[$VM.Name]) {
                # Using previously calculated credentials from shutdown job.
                $Creds = $VMCreds[$VM.Name]
                Write-Host "$(Get-Date -Format G): Starting $($VM.Name)."

                try {
                    $VM = Start-VM -VM $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                } catch {
                    Write-Host "$(Get-Date -Format G): Unable to start $($VM.Name)." -BackgroundColor Red `
                        -ForegroundColor Yellow
                    $Configuration.ScriptErrors += "$(Get-Date -Format G): WARNING: Unable to start $($VM.Name)."
                }

                $PowerShell = [powershell]::Create()
                $PowerShell.RunspacePool = $RunspacePool
                $null = $PowerShell.AddScript($BootWorker).AddArgument($VM).AddArgument($Creds).AddArgument($Configuration)

                $JobObj = New-Object -TypeName PSObject -Property @{
                    Runspace   = $PowerShell.BeginInvoke()
                    PowerShell = $PowerShell
                }

                $null = $Jobs.Add($JobObj)
                $RSPercentComplete = ($VMIdx / $GroupCount).ToString('P')
                $Activity = "Runspace creation for bootup: Processing $VM, Stage $Stage, Group $group"
                $Status = "$VMIdx/$GroupCount : $RSPercentComplete Complete"
                $CleanPercent = $RSPercentComplete.Replace('%', '')
                Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $CleanPercent

                $VMIdx++
            } else {
                Write-Host "$(Get-Date -Format G): Skipping $($VM.Name) because it failed during shutdown phase." `
                    -BackgroundColor DarkRed -ForegroundColor Yellow
            }
        }

        Write-Progress -Id 1 -Activity "Runspace creation for stage $Stage, group $group" -Completed

        # Used to determine percentage completed.
        $TotalJobs = $Jobs.Runspace.Count

        Write-Progress -Id 2 -Activity 'Booting' -Status 'Booting machines.' -PercentComplete 0

        # Update percentage complete and wait until all jobs are finished.
        while ($Jobs.Runspace.IsCompleted -contains $false) {
            $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
            $PercentComplete = ($CompletedJobs / $TotalJobs).ToString('P')
            $Status = "$CompletedJobs/$TotalJobs : $PercentComplete Complete"
            Write-Progress -Id 2 -Activity "Booting machines; Stage $Stage, Group $group" -Status $Status `
                -PercentComplete $PercentComplete.Replace('%', '')
            Start-Sleep -Milliseconds 100
        }

        # Clean up runspace.
        $RunspacePool.Close()

        Write-Progress -Id 2 -Activity 'Booting machines' -Completed
    }

    Write-Host "Completed stage $Stage."

    # Do not wait after the final stage
    if ($StageIdx -lt $TotalStages) {
        Wait-Stage -Action 'Time' -Message "Waiting $($Settings.MinsBtwStages) minutes before starting next stage."
    }

    #Increment the stage count
    $StageIdx++
}
# Disconnect from vCenter
Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false

# Write script errors to log file
if (Test-Path -Path $ScriptErrors -PathType leaf) { Clear-Content -Path $ScriptErrors }
Add-Content -Path $ScriptErrors -Value $Configuration.ScriptErrors

Write-Host "$(Get-Date -Format G): Script error log saved to $ScriptErrors"

# Deleting services CSV since script completed run
Remove-Item -Path $ScriptOutput -Force

$wshell = New-Object -ComObject Wscript.Shell
$elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
$null = $wshell.Popup("Operation Completed in $elapsedMinutes minutes", 0, 'Done', $Buttons.OK + $Icon.Information)
#####END OF SCRIPT#######