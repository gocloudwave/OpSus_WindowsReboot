#Requires -Version 5.1
#Requires -PSEdition Desktop

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
    'AbortRetryIgnore'       = 2
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
$Configuration.BootFailure = @()
$Configuration.VIServer = $null
$Configuration.CredsTest = @{}
$Configuration.InterimProcess = 'Reboot'

$ButtonClicked = $null
$ADCreds = $null
$LMCreds = $null
$ADSecrets = $null
$LMSecrets = $null
$VMCreds = @{}
$VMTestGroup = @()

Import-Module -Name VMware.PowerCLI -MinimumVersion 13.1.0.21624340 -Force -NoClobber
Import-Module -Name Thycotic.SecretServer -RequiredVersion 0.61.0 -Force -NoClobber

. "$PSScriptRoot\User-Prompts.ps1"

# Prompt user for JSON file with settings
$SettingsFile = Get-FileName -initialDirectory $PSScriptRoot -title 'Select JSON file with customer settings' `
    -filter 'JavaScript Object Notation files (*.json)|*.json'

$Settings = Get-Content $SettingsFile -Raw | ConvertFrom-Json
$Configuration.SvcWhitelist = $Settings.SvcWhitelist
$Configuration.Timeout = $Settings.Timeout

# Display settings details and ask user to confirm continuation of script
if ($Settings.TssFolder) {
    $wshell = New-Object -ComObject Wscript.Shell
    $ButtonClicked = $wshell.Popup('Do you want to process the customer in Thycotic folder ' +
        "$($Settings.TssFolder)?", 0, 'Confirm customer', $Buttons.YesNo + $Icon.Question)
}

# Exit script if Customer field empty or if user selected no.
if ($null -eq $ButtonClicked -or $ButtonClicked -eq $Selection.No) { Exit 1223 }

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

# Function to wait between stages
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

function Invoke-Parallelization {
    [CmdletBinding()]
    param (
        # Servers to process
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 0)]
        [PSObject] $Servers,
        # Activity message for runspace creation progress bar
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 1)]
        [string] $RunspaceCreationActivity,
        # Local Machine credentials
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 2)]
        [System.Management.Automation.PSCredential] $LMCreds,
        # Active Directory credentials
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 3)]
        [System.Management.Automation.PSCredential] $ADCreds,
        # Worker script block
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 4)]
        [scriptblock] $WorkerScript,
        # Configuration data
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 5)]
        [hashtable] $Configuration,
        # Activity messages for worker progress bar
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 6)]
        [string] $WorkerActivity,
        # Status messages for worker progress bar
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 7)]
        [string] $WorkerStatus,
        # VM Credentials
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName, Position = 8)]
        [hashtable] $VMCreds
    )

    begin {
        $ServerCount = $Servers.Count
        if ($null -eq $ServerCount) { $ServerCount = 1 }
        # Set minimum runspaces to 20 or server count, whichever is lower.
        $MinimumRunspaces = [Math]::Min($ServerCount, 20)
        # Process no more than 25% of the list at once.
        $MaxRunspaces = [Math]::Max([Math]::Ceiling($ServerCount / 4), $MinimumRunspaces)

        # Create runspace pool for parralelization
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
        $RunspacePool.Open()

        $Jobs = New-Object System.Collections.ArrayList
        if ($WorkerScript -eq $BootWorker) {
            $SleepMilliseconds = 1000
        } else {
            $SleepMilliseconds = 100
        }
    }

    process {
        # Display progress bar
        $WriteProgressParams = @{
            Activity        = $RunspaceCreationActivity
            Status          = "Creating runspaces for $ServerCount VMs."
            PercentComplete = 0
        }
        Write-Progress @WriteProgressParams

        $VMindex = 1
        # Create job for each VM

        foreach ($VM in $Servers) {
            # Save credentials to hashtable for later use if running FirstRebootWorker
            if ($WorkerScript -eq $FirstRebootWorker -or $WorkerScript -eq $TestCredentials) {
                if ($VM.Guest.HostName -notlike '*.*') {
                    $Creds = $LMCreds
                } else {
                    $Creds = $ADCreds
                }

                $VMCreds[$VM.Name] = $Creds
            } else {
                $Creds = $VMCreds[$VM.Name]
            }

            # Skip VM if it failed during shutdown phase and this isn't the test credential or first reboot phase
            if (
                ($WorkerScript -eq $InterimWorker -or $WorkerScript -eq $BootWorker) -and
                $Configuration.Shutdown[$VM.Name] -eq $false
            ) {
                Write-Host "$(Get-Date -Format G): Skipping $($VM.Name) because it failed during first reboot." `
                    -BackgroundColor DarkRed -ForegroundColor Yellow
                continue
            }

            $PowerShell = [powershell]::Create()
            $PowerShell.RunspacePool = $RunspacePool
            $null = $PowerShell.AddScript($WorkerScript).AddArgument($VM).AddArgument($Creds).AddArgument($Configuration)

            $JobObj = New-Object -TypeName PSObject -Property @{
                Runspace   = $PowerShell.BeginInvoke()
                Name       = $VM.Name
                PowerShell = $PowerShell
            }

            $null = $Jobs.Add($JobObj)
            $CompletedJobs = $VMindex / $ServerCount
            $WriteProgressParams = @{
                Activity        = $RunspaceCreationActivity
                Status          = "$VMindex/$ServerCount"
                PercentComplete = ($CompletedJobs / $ServerCount ) * 100
            }
            Write-Progress @WriteProgressParams

            $VMindex++
        }

        Write-Progress -Activity $RunspaceCreationActivity -Completed

        # Used to determine percentage completed.
        $TotalJobs = $Jobs.Runspace.Count

        Write-Progress -Activity $WorkerActivity -Status $WorkerStatus -PercentComplete 0

        # Update percentage complete and wait until all jobs are finished.
        while ($Jobs.Runspace.IsCompleted -contains $false) {
            $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
            $WriteProgressParams = @{
                Activity        = $WorkerActivity
                Status          = "$CompletedJobs/$TotalJobs"
                PercentComplete = ($CompletedJobs / $TotalJobs ) * 100
            }
            Write-Progress @WriteProgressParams
            if ($WorkerScript -eq $BootWorker) {
                $currtime = Get-Date -Format mm:ss
                $currtime_lastfour = $currtime.Substring($currtime.length - 4, 4)
                if ($currtime_lastfour -eq '0:00' -Or $currtime_lastfour -eq '5:00') {
                    foreach ($j in $Jobs | Where-Object { -Not $_.Runspace.IsCompleted }) {
                        $msg = "$(Get-Date -Format G): Waiting for services to start on $($j.Name). If five mins "
                        $msg += "have passed, obtain service list from $ScriptOutput and check the server manually."
                        Write-Host $msg
                    }
                }
            }
            Start-Sleep -Milliseconds $SleepMilliseconds
        }
    }

    end {
        # Clean up runspace.
        $RunspacePool.Close()

        Write-Progress -Activity $WorkerStatus -Completed
    }
}

# Use invalid certificate action from settings.json
$null = Set-PowerCLIConfiguration -InvalidCertificateAction $Settings.InvalidCertAction -Scope Session `
    -Confirm:$false

# Connect to vCenter using logged on user credentials
while ($null -eq $Configuration.VIServer) { $Configuration.VIServer = Connect-VIServer $Settings.vCenter }

# Create VMTable using -Get-VM -Tag with category "Customer" and Name $Settings.Customer. Table will have VM Name,
# "CC+ Process" category tag value, "CC+ Boot Group" category tag value, "CC+ Shutdown Group" category tag value,
# and "CC+ Stage" category tag value. Sort by Stage, BootGroup, and Name.
$VMTable = Get-VM -Tag $(Get-Tag -Name $Settings.Customer -Category 'Customer' -Server $Configuration.VIServer) |
    Select-Object Name,
    @{ Name = 'Process'; Expression = { (Get-TagAssignment -Entity $_ -Category 'CC+ Process').Tag.Name } },
    @{ Name = 'BootGroup'; Expression = { (Get-TagAssignment -Entity $_ -Category 'CC+ Boot Group').Tag.Name } },
    @{ Name = 'ShutdownGroup'; Expression = { (Get-TagAssignment -Entity $_ -Category 'CC+ Shutdown Group').Tag.Name } },
    @{ Name = 'Stage'; Expression = { (Get-TagAssignment -Entity $_ -Category 'CC+ Stage').Tag.Name } },
    @{ Name = 'VM Tools Version'; Expression = { $_.ExtensionData.Guest.toolsVersion } } |
    Sort-Object Process, Stage, BootGroup, ShutdownGroup, Name

# Output table to screen for user to verify.
$VMTable | Format-Table -AutoSize

# Prompt user to confirm processing of VMs. If user selects no, exit script.
$ButtonClicked = $null
$ButtonClicked = $wshell.Popup('Do you want to process the VMs as listed?', 0, 'Confirm VMs', `
        $Buttons.YesNo + $Icon.Question)

if ($ButtonClicked -eq $Selection.No) {
    # Disconnect from vCenter
    Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false
    # Exit script with no error
    Exit 0
}

# Prompt user for location of output files
Add-Type -AssemblyName System.Windows.Forms
$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$FolderBrowser.Description = 'Select a folder in which to store logs and temporary files.'
[void]$FolderBrowser.ShowDialog()

$ScriptOutput = "$($FolderBrowser.SelectedPath)\$(Get-Date -Format FileDateUniversal)-Services.csv"
$UnvOutput = "$($FolderBrowser.SelectedPath)\$(Get-Date -Format FileDateUniversal)-UNV-Services.csv"
$ScriptErrors = "$($FolderBrowser.SelectedPath)\$(Get-Date -Format FileDateUniversal)-ScriptErrors.log"
$ADTssTemplateId = $Settings.SecretTemplateLookup.ActiveDirectoryAccount
$LMTssTemplateId = $Settings.SecretTemplateLookup.LocalUserWindowsAccount
$TssUsername = "$($Settings.TssDomain)\$($Settings.TssUser)"

# Prompt user if they want to update VMware Tools
$Configuration.UpdateVMTools = $false
$ButtonClicked = $null
$ButtonClicked = $wshell.Popup('Do you want to update VMware Tools?', 0, 'Update VMware Tools', `
        $Buttons.YesNo + $Icon.Question)

if ($ButtonClicked -eq $Selection.Yes) {
    $Configuration.UpdateVMTools = $true
}

if ($Configuration.UpdateVMTools) {
    # Prompt user for desired version of VMware Tools
    $Configuration.VMToolsDesiredVersion = Enter-StringDialogBox -Title 'VMware Tools' `
        -Prompt 'What version of VMware Tools should be installed?' -Height 150 -Width 350

    # Ensure user didn't cancel the dialog box or click OK without entering text
    if ($null -eq $Configuration.VMToolsDesiredVersion -or $Configuration.VMToolsDesiredVersion -eq '') {
        $wshell = New-Object -ComObject Wscript.Shell
        $msg = 'User canceled VMware Tools version selection. Exiting script.'
        $null = $wshell.Popup($msg, 0, 'Exiting', $Buttons.OK + $Icon.Exclamation)
        Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false
        Exit 1223
    }

    # Prompt user for path to VMware Tools executable
    $Configuration.VMToolsExecutablePath = Get-FileName -initialDirectory $PSScriptRoot `
        -title 'Select VMware Tools executable file' -filter 'Executable files (*.exe)|*.exe'
}

$VMTable | Add-Member -MemberType NoteProperty -Name 'Processed' -Value $false

# Drop all rows that the script shouldn't process
$VMTable = $VMTable | Where-Object { $_.Process -ceq 'TRUE' }

$Stages = $VMTable.Stage | Sort-Object -Unique -CaseSensitive
$TotalStages = $Stages.Count
if ($null -eq $TotalStages) { $TotalStages = 1 }

try {
    $VMs = Get-VM -Name $VMTable.Name -Server $Configuration.VIServer
} catch {
    # Disconnect from vCenter
    Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false
    $wshell = New-Object -ComObject Wscript.Shell
    $errMsg = "Error Message: $($_.Exception.Message)"
    $msg = "A VM is in the CSV that doesn't exist on the vCenter server. Please check the CSV. $errMsg"
    $null = $wshell.Popup($msg, 0, 'Exiting', $Buttons.OK + $Icon.Exclamation)

    Exit 1223
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
        $TssFolders = Search-TssFolders -TssSession $Session -SearchText $Settings.TssFolder `
            -ErrorAction $ErrorActionPreference
    } catch {
        # Unable to find the folder specified in settings.json. Listing all top level folders.
        $TssFolders = Search-TssFolders -TssSession $Session -ParentFolderId -1 -ErrorAction $ErrorActionPreference
    }

    if (($TssFolders.Count -eq 1) -or ($null -eq $TssFolders.Count)) {
        $TssFolder = $TssFolders
    } else {
        $Prompt = "Please select the Secret Folder (found $($TssFolders.Count)):"
        $TssFolderName = Select-SingleOptionDialogBox -Title 'Select a folder:' `
            -Prompt $Prompt -Values $TssFolders.FolderName

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
        $ADSecretName = Select-SingleOptionDialogBox -Title 'Select a secret' `
            -Prompt 'Please select the Domain Admin Secret:' -Values $ADSecrets.SecretName
    }

    # Select Local Admin secret
    if ($LMSecrets) {
        $Prompt = 'Please select the Local Machine Admin Secret:'
        $LMSecretName = Select-SingleOptionDialogBox -Title 'Select a secret' `
            -Prompt $Prompt -Values $LMSecrets.SecretName
    }

    # Obtain Domain Admin credentials
    if ($null -eq $ADSecretName) {
        $ADCreds = Get-UserCredentials -Type 'AD Administrator' -Customer $Settings.TssFolder
    } else {
        $ADCreds = Get-UserCredentials -Type 'AD Administrator' -Customer $Settings.TssFolder -TssSession $Session `
            -TssFolder $TssFolder -TssRecords $ADSecrets -SecretName $ADSecretName
    }

    # Obtain Local Machine Admin credentials
    if ($null -eq $LMSecretName) {
        $LMCreds = Get-UserCredentials -Type 'Local Machine' -Customer $Settings.TssFolder
    } else {
        $LMCreds = Get-UserCredentials -Type 'Local Machine' -Customer $Settings.TssFolder -TssSession $Session `
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

    begin {
        $ErrorActionPreference = 'Stop'
        $Error.Clear()
        $ScriptText = 'try { Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop } ' +
        "catch { Write-Warning 'Access denied' }"
        $prevProgressPreference = $global:ProgressPreference
    }

    process {
        try {
            $global:ProgressPreference = 'SilentlyContinue'
            $InvokeVMScriptParams = @{
                Server          = $Configuration.VIServer
                VM              = $VM
                ScriptText      = $ScriptText
                GuestCredential = $VMcreds
                ErrorAction     = $ErrorActionPreference
            }
            $TestAccess = Invoke-VMScript @InvokeVMScriptParams 3> $null

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

    end {
        $global:ProgressPreference = $prevProgressPreference
    }

}

# Script block to parallelize collecting VM data and rebooting the VM
$FirstRebootWorker = {
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

        $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference

        $SvcWhitelist = "'$($($Configuration.SvcWhitelist) -join "','")'"

        $ScriptText = ("try { Get-Service -Include $SvcWhitelist -ErrorAction Stop | Where-Object { " +
            '$_.StartType -eq "Automatic" -and $_.Status -eq "Running" } | Format-Table -Property Name ' +
            '-HideTableHeaders } catch { Write-Warning "Access denied" }')
        $prevProgressPreference = $global:ProgressPreference

        # Function to check if $TimeoutCounter has exceeded the timeout value
        function CheckTimeout {
            if ($TimeoutCounter.Elapsed.TotalMinutes -gt $Configuration.Timeout) {
                $msg = "$(Get-Date -Format G): $($VM.Name) failed to boot in $($Configuration.Timeout) " +
                'minutes. Logging.'
                throw [System.TimeoutException] $msg
            }
        }
    }

    process {
        try {
            $global:ProgressPreference = 'SilentlyContinue'
            Write-Host "$(Get-Date -Format G): INFO: Attempting service collection on $($VM.Name)."
            $InvokeVMScriptParams = @{
                Server          = $Configuration.VIServer
                VM              = $VM
                ScriptText      = $ScriptText
                GuestCredential = $VMcreds
                ErrorAction     = $ErrorActionPreference
            }
            $CollectedServices = Invoke-VMScript @InvokeVMScriptParams 3> $null

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

                    $CollectedServices = Invoke-VMScript @InvokeVMScriptParams 3> $null

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

                if ($VM.ExtensionData.Guest.toolsRunningStatus -ne 'guestToolsNotRunning') {
                    Write-Host "$(Get-Date -Format G): Shutting down $($VM.Name)."
                    $null = Stop-VMGuest -VM $VM -Server $Configuration.VIServer -Confirm:$false
                    $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                } else {
                    Write-Host "$(Get-Date -Format G): Stopping $($VM.Name)."
                    $VM = Stop-VM -VM $VM -Server $Configuration.VIServer -Confirm:$false
                }
                $Configuration.Shutdown[$VM.Name] = $true

                while ($VM.PowerState -ne 'PoweredOff') {
                    Start-Sleep -Seconds 30
                    $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                    $msg = "$(Get-Date -Format G): Waiting for $($VM.Name) to shut down."
                    if ($VM.PowerState -ne 'PoweredOff') {
                        $msg += " Power state: $($VM.PowerState). Power state must be PoweredOff."
                    }
                    Write-Host $msg
                }

                # Wait an additional 30 seconds to ensure the VM is fully shut down
                Start-Sleep -Seconds 30

                $TimeoutCounter = [System.Diagnostics.Stopwatch]::StartNew()

                $VM = Start-VM -VM $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference

                while (($VM.PowerState -ne 'PoweredOn') -or (![bool]$VM.Guest.HostName)) {
                    try {
                        CheckTimeout -ErrorAction $ErrorActionPreference
                    } catch [System.TimeoutException] {
                        Write-Host $_.Exception.Message -BackgroundColor Magenta -ForegroundColor Cyan
                        break
                    }
                    $msg = "$(Get-Date -Format G): Starting $($VM.Name)."
                    if ($VM.PowerState -ne 'PoweredOn') {
                        $msg += " Power state: $($VM.PowerState). Power state must be PoweredOn."
                    }
                    if (![bool]$VM.Guest.HostName) {
                        $msg += " Hostname: $($VM.Guest.HostName). Hostname must not be empty."
                    }
                    # If PowerState isn't on or hostname is null, add message telling user the script is waiting 30
                    # seconds before checking again.
                    if ($VM.PowerState -ne 'PoweredOn' -or ![bool]$VM.Guest.HostName) {
                        $msg += ' Waiting 30 seconds before checking again.'
                    }
                    Write-Host $msg
                    Start-Sleep -Seconds 30
                    $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                }
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
                'VM to ensure it is working properly. Error message and attempted command in log file.')
            Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
            $ErrorMessage = ("$(Get-Date -Format G): SHUTDOWN WARNING: Unable to process $($VM.Name). Check the " +
                'VM to ensure it is working properly. Error message and attempted command below:')
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

    end {
        $global:ProgressPreference = $prevProgressPreference
        $TimeoutCounter.Stop()
    }
}

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

        $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
        # Run two Powershell commands with one Invoke-VMScript.
        # Get service status for all services in ServicesList and use while loop to wait until all services are
        # running.
        if ($Configuration.Services | Where-Object { $_.VM -eq $VM.Name }) {
            $ServerServices = ($Configuration.Services | Where-Object { $_.VM -eq $VM.Name -and
                    $_.ServiceName -notmatch '^MEDITECH\sUNV\s.*' }).ServiceName
        }

        $ServiceList = "'$($ServerServices -join "','")'"
        $ScriptText = ('$Services = ' + "$ServiceList; try { while (Get-Service -Include " + '$Services | ' +
            'Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | Format-Table -Property' +
            ' Name -HideTableHeaders ) { Start-Sleep -Seconds 1 } } catch { Write-Warning "Access denied" }')

        $prevProgressPreference = $global:ProgressPreference

        # Wait 60 seconds so VM has time to obtain DNS HostName
        Start-Sleep -Seconds 60
        $TimeoutCounter = [System.Diagnostics.Stopwatch]::StartNew()

        # Function to check if $TimeoutCounter has exceeded the timeout value
        function CheckTimeout {
            if ($TimeoutCounter.Elapsed.TotalMinutes -gt $Configuration.Timeout) {
                $msg = "$(Get-Date -Format G): $($VM.Name) failed to boot in $($Configuration.Timeout) " +
                'minutes. Logging.'
                throw [System.TimeoutException] $msg
            }
        }
    }

    process {
        try {
            $global:ProgressPreference = 'SilentlyContinue'
            # Start VM if it is not already powered on. Log message if VM is already powered on.
            if ($VM.PowerState -ne 'PoweredOn') {
                Write-Host "$(Get-Date -Format G): Starting $($VM.Name)."
                $VM = Start-VM -VM $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
            } else {
                Write-Host "$(Get-Date -Format G): $($VM.Name) is already powered on."
            }

            # Wait for VM power state ON and DNS Name assignment
            while (($VM.PowerState -ne 'PoweredOn') -or (![bool]$VM.Guest.HostName)) {
                try {
                    CheckTimeout -ErrorAction $ErrorActionPreference
                } catch [System.TimeoutException] {
                    Write-Host $_.Exception.Message -BackgroundColor Magenta -ForegroundColor Cyan
                    break
                }
                # Give the machine time before attempting login after boot up
                $msg = "$(Get-Date -Format G): Starting $($VM.Name)."
                if ($VM.PowerState -ne 'PoweredOn') {
                    $msg += " Power state: $($VM.PowerState). Power state must be PoweredOn."
                }
                if (![bool]$VM.Guest.HostName) {
                    $msg += " Hostname: $($VM.Guest.HostName). Hostname must not be empty."
                }
                Write-Host $msg
                Start-Sleep -Seconds 30
                $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
            }

            # Run script to check services.
            if ($ServerServices) {
                $msg = "$(Get-Date -Format G): Checking the following Automatic and Running services on " + `
                    "$($VM.Name): ($ServiceList)"
                Write-Host $msg -BackgroundColor DarkGreen -ForegroundColor Green
                $InvokeVMScriptParams = @{
                    Server          = $Configuration.VIServer
                    VM              = $VM
                    ScriptText      = $ScriptText
                    GuestCredential = $VMcreds
                    ErrorAction     = $ErrorActionPreference
                }
                $ServicesCheck = Invoke-VMScript @InvokeVMScriptParams 3> $null

                while ($ServicesCheck.ScriptOutput -like 'WARNING: Access denied*') {
                    try {
                        CheckTimeout -ErrorAction $ErrorActionPreference
                    } catch [System.TimeoutException] {
                        Write-Host $_.Exception.Message -BackgroundColor Magenta -ForegroundColor Cyan
                        break
                    }
                    Write-Host "$(Get-Date -Format G): $($VM.Name) failed login. Waiting 60s and trying again." `
                        -BackgroundColor Yellow -ForegroundColor DarkRed
                    Start-Sleep -Seconds 60

                    # Run script to check services.
                    $InvokeVMScriptParams = @{
                        Server          = $Configuration.VIServer
                        VM              = $VM
                        ScriptText      = $ScriptText
                        GuestCredential = $VMcreds
                        ErrorAction     = $ErrorActionPreference
                    }
                    $ServicesCheck = Invoke-VMScript @InvokeVMScriptParams 3> $null
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
                'to ensure it is working properly. Error message and attempted command in log file.')
            Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
            $ErrorMessage = ("$(Get-Date -Format G): BOOT WARNING: Unable to process $($VM.Name). Check the VM " +
                'to ensure it is working properly. Error message and attempted command below:')
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [System.TimeoutException] {
            Write-Host $Error[0].Exception.Message -BackgroundColor Red -ForegroundColor Yellow
            $Configuration.ScriptErrors += $Error[0].Exception.Message
            # Log name of server that failed to boot
            $Configuration.BootFailure += $VM.Name
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

    end {
        $global:ProgressPreference = $prevProgressPreference
        $TimeoutCounter.Stop()
    }
}

# Script block to parallelize collecting VM data and shutting down the VM
$InterimWorker = {
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

        $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference

        $prevProgressPreference = $global:ProgressPreference

        # Function to check if $TimeoutCounter has exceeded the timeout value
        function CheckTimeout {
            if ($TimeoutCounter.Elapsed.TotalMinutes -gt $Configuration.Timeout) {
                $msg = "$(Get-Date -Format G): $($VM.Name) failed to boot in $($Configuration.Timeout) " +
                'minutes. Logging.'
                throw [System.TimeoutException] $msg
            }
        }
    }

    process {
        $global:ProgressPreference = 'SilentlyContinue'
        # Skip servers that failed to shutdown during FirstRebootWorker
        if ($Configuration.Shutdown[$VM.Name] -eq $false) {
            Write-Host "$(Get-Date -Format G): Skipping $($VM.Name) due to previous failure."
            return
        }

        # Try/Catch block to handle errors during VMtools installation
        try {
            # Update VMTools if necessary
            if ($Configuration.UpdateVMTools) {
                $TempPath = 'C:\Temp\'
                $VMToolsExecutable = Split-Path $Configuration.VMToolsExecutablePath -Leaf
                $VMToolsInstallationScript = ("$TempPath\$VMToolsExecutable /S /v " + '"/qn REBOOT=R ' +
                    'ADDLOCAL=ALL REMOVE=Hgfs"')
                $PostVMToolsInstallationScript = ("Remove-Item -Path '$TempPath\$VMToolsExecutable' -Force; " +
                    'Clear-RecycleBin -Confirm:$False')
                # Check if VMware Tools is installed and at the desired version
                if ($VM.ExtensionData.Guest.toolsVersion -ne $Configuration.VMToolsDesiredVersion) {
                    Write-Host "$(Get-Date -Format G): Upgrading VMware Tools on $($VM.Name)."
                    # Copy VMtools executable to VM
                    $CopyVMGuestFileParams = @{
                        Server          = $Configuration.VIServer
                        Source          = $Configuration.VMToolsExecutablePath
                        Destination     = 'C:\Temp\'
                        VM              = $VM
                        GuestCredential = $VMcreds
                        LocalToGuest    = $true
                        Force           = $true
                        ErrorAction     = $ErrorActionPreference
                    }
                    Copy-VMGuestFile @CopyVMGuestFileParams 3> $null

                    # Install VMtools; Run Asynchronously because the script will 'fail' during installation
                    $InvokeVMScriptParams = @{
                        Server          = $Configuration.VIServer
                        VM              = $VM
                        ScriptText      = $VMToolsInstallationScript
                        GuestCredential = $VMcreds
                        RunAsync        = $true
                        # ErrorAction     = 'SilentlyContinue' # Connectivity to guest VM drops when upgrading tools
                    }
                    $null = Invoke-VMScript @InvokeVMScriptParams 3> $null

                    $SleepSeconds = 5
                    $Timeout = 300
                    $ElapsedTime = 0
                    while ($ElapsedTime -lt $Timeout) {
                        $VM = Get-VM -Name $VM.Name -Server $Configuration.VIServer
                        if ($VM.ExtensionData.Guest.toolsVersion -eq $Configuration.VMToolsDesiredVersion) {
                            break
                        }
                        $ElapsedTime += $SleepSeconds
                        Start-Sleep -Seconds $SleepSeconds
                    }

                    # Post VMtools installation cleanup
                    $InvokeVMScriptParams = @{
                        Server          = $Configuration.VIServer
                        VM              = $VM
                        ScriptText      = $PostVMToolsInstallationScript
                        GuestCredential = $VMcreds
                        ErrorAction     = $ErrorActionPreference
                    }
                    $null = Invoke-VMScript @InvokeVMScriptParams 3> $null
                }
            }

            if ($VM.ExtensionData.Guest.toolsRunningStatus -ne 'guestToolsNotRunning') {
                Write-Host "$(Get-Date -Format G): Shutting down $($VM.Name)."
                $null = Stop-VMGuest -VM $VM -Server $Configuration.VIServer -Confirm:$false
                $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
            } else {
                Write-Host "$(Get-Date -Format G): Stopping $($VM.Name)."
                $VM = Stop-VM -VM $VM -Server $Configuration.VIServer -Confirm:$false
            }

            while ($VM.PowerState -ne 'PoweredOff') {
                Start-Sleep -Seconds 30
                $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                $msg = "$(Get-Date -Format G): Waiting for $($VM.Name) to shut down."
                if ($VM.PowerState -ne 'PoweredOff') {
                    $msg += " Power state: $($VM.PowerState). Power state must be PoweredOff."
                }
                Write-Host $msg
            }

            # Wait an additional 30 seconds to ensure the VM is fully shut down
            Start-Sleep -Seconds 30

            if ($Configuration.InterimProcess -eq 'Reboot') {
                Write-Host "$(Get-Date -Format G): Rebooting $($VM.Name)."
                $TimeoutCounter = [System.Diagnostics.Stopwatch]::StartNew()

                $VM = Start-VM -VM $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference

                while (($VM.PowerState -ne 'PoweredOn') -or (![bool]$VM.Guest.HostName)) {
                    try {
                        CheckTimeout -ErrorAction $ErrorActionPreference
                    } catch [System.TimeoutException] {
                        Write-Host $_.Exception.Message -BackgroundColor Magenta -ForegroundColor Cyan
                        break
                    }
                    # Give the machine time before attempting login after boot up
                    $msg = "$(Get-Date -Format G): Rebooting $($VM.Name)."
                    if ($VM.PowerState -ne 'PoweredOn') {
                        $msg += " Power state: $($VM.PowerState). Power state must be PoweredOn."
                    }
                    if (![bool]$VM.Guest.HostName) {
                        $msg += " Hostname: $($VM.Guest.HostName). Hostname must not be empty."
                    }
                    # If PowerState isn't on or hostname is null, add message telling user the script is waiting 30
                    # seconds before checking again.
                    if ($VM.PowerState -ne 'PoweredOn' -or ![bool]$VM.Guest.HostName) {
                        $msg += ' Waiting 30 seconds before checking again.'
                    }
                    Write-Host $msg
                    Start-Sleep -Seconds 30
                    $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                }
            }
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
            $ErrorMessage = ("$(Get-Date -Format G): INTERIM WARNING: The credentials for $($VMcreds.Username) " +
                "do not work on $($VM.Name). If this is a one-off error, please correct the credentials on the " +
                'server. If this error repeats often, then update the credentials in Thycotic.')
            Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
            $msg = "$(Get-Date -Format G): INTERIM WARNING: Invalid argument processing $($VM.Name)."
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
            $msg = "$(Get-Date -Format G): INTERIM WARNING: Failure connecting to $($VM.Name)."
            Write-Host $msg -BackgroundColor Magenta -ForegroundColor Cyan
            $Configuration.ScriptErrors += $msg
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
            $ErrorMessage = ("$(Get-Date -Format G): INTERIM WARNING: Unable to process $($VM.Name). Check the " +
                'VM to ensure it is working properly. Error message and attempted command in log file.')
            Write-Host $ErrorMessage -BackgroundColor Magenta -ForegroundColor Cyan
            $ErrorMessage = ("$(Get-Date -Format G): INTERIM WARNING: Unable to process $($VM.Name). Check the " +
                'VM to ensure it is working properly. Error message and attempted command below:')
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch {
            $msg = "$(Get-Date -Format G): INTERIM WARNING: Other error processing $($VM.Name)."
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

    end {
        $global:ProgressPreference = $prevProgressPreference
        $TimeoutCounter.Stop()
    }
}


$VMTestGroup += $VMs | Where-Object { $_.Guest.HostName -notlike '*.*' }
$VMTestGroup += $VMs | Where-Object { $_.Guest.HostName -like '*.*' } | Get-Random

# Test credentials for all VMs
$TestCredentialsParams = @{
    Servers                  = $VMTestGroup
    RunspaceCreationActivity = 'Creating Runspaces to test credentials'
    LMCreds                  = $LMCreds
    ADCreds                  = $ADCreds
    WorkerScript             = $TestCredentials
    Configuration            = $Configuration
    WorkerActivity           = 'Testing credentials'
    WorkerStatus             = 'Verifying credentials'
    VMCreds                  = $VMCreds
}

Invoke-Parallelization @TestCredentialsParams

if ($Configuration.CredsTest.ContainsValue('FAIL')) {
    # Clean up and exit script
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
    # $Stage is the current item
    Write-Host "Starting stage $Stage."
    $StageTable = $VMTable | Where-Object { $_.Stage -ceq $Stage }
    $StageCount = $StageTable.Count
    if ($null -eq $StageCount) { $StageCount = 1 }
    $BootGroups = $StageTable.BootGroup | Sort-Object -Unique -CaseSensitive
    $ShutdownGroups = $StageTable.ShutdownGroup | Sort-Object -Unique -CaseSensitive
    $StageServers = $VMs | Where-Object { $_.Name -in $StageTable.Name }

    $StageTable = $StageTable | Sort-Object -Property ShutdownGroup, Name -CaseSensitive

    foreach ($ShutdownGroup in $ShutdownGroups) {
        Write-Host "Starting Shutdown Group $ShutdownGroup."
        $ShutdownServers = $VMs | Where-Object { $_.Name -in (
                $StageTable | Where-Object { $_.ShutdownGroup -ceq $ShutdownGroup }).Name }

        # Shutdown Parameters
        $ShutdownParams = @{
            Servers                  = $ShutdownServers
            RunspaceCreationActivity = "Creating Runspaces for stage $Stage, Group $ShutdownGroup"
            LMCreds                  = $LMCreds
            ADCreds                  = $ADCreds
            WorkerScript             = $FirstRebootWorker
            Configuration            = $Configuration
            WorkerActivity           = "Collecting services and shutting down; Stage $Stage, Group $ShutdownGroup"
            WorkerStatus             = 'Shutting down.'
            VMCreds                  = $VMCreds

        }

        Invoke-Parallelization @ShutdownParams

        Write-Host "Finished Shutdown Group $ShutdownGroup."
    }

    # Write services data to CSV. If manual intervention is needed, user can access this file to check services.
    if (Test-Path -Path $ScriptOutput -PathType leaf) { Clear-Content -Path $ScriptOutput }
    $Configuration.Services | Export-Csv -Path $ScriptOutput -NoTypeInformation -Force
    if (Test-Path -Path $UnvOutput -PathType leaf) { Clear-Content -Path $UnvOutput }
    $Congifuration.Services | Where-Object { $_.ServiceName -match '^MEDITECH\sUNV\s.*' } | `
            Export-Csv -Path $UnvOutput -NoTypeInformation -Force

    Write-Host "$(Get-Date -Format G): Services list saved to $ScriptOutput"

    $wshell = New-Object -ComObject Wscript.Shell
    $ButtonClicked = $wshell.Popup('Do any servers require another patching reboot?', 0, 'Additional Patches', `
            $Buttons.YesNo + $Icon.Question)

    while ($ButtonClicked -eq $Selection.Yes) {
        $VMsSelected = Select-MultiOptionDialogBox -Title 'Select VMs to reboot' -Prompt 'Select VMs to reboot' `
            -Values ($StageTable.Name) -Height 500

        if ($null -eq $VMsSelected) {
            $ButtonClicked = $wshell.Popup('Do any servers require another patching reboot?', 0, 'Additional Patches', `
                    $Buttons.YesNo + $Icon.Question)
            continue
        }

        $VMsToReboot = $VMs | Where-Object { $_.Name -in $VMsSelected }
        $RebootParams = @{
            Servers                  = $VMsToReboot
            RunspaceCreationActivity = "Creating Runspaces for stage $Stage"
            LMCreds                  = $LMCreds
            ADCreds                  = $ADCreds
            WorkerScript             = $InterimWorker
            Configuration            = $Configuration
            WorkerActivity           = "Rebooting machines; Stage $Stage"
            WorkerStatus             = 'Rebooting machines.'
            VMCreds                  = $VMCreds
        }

        Invoke-Parallelization @RebootParams

        $ButtonClicked = $wshell.Popup('Do any servers require another patching reboot?', 0, 'Additional Patches', `
                $Buttons.YesNo + $Icon.Question)
    }

    $Configuration.InterimProcess = 'Shutdown'

    # Perform final shutdown using InterimWorker in preparation of booting in correct order
    $ShutdownParams = @{
        Servers                  = $StageServers
        RunspaceCreationActivity = "Creating Runspaces for Stage $Stage"
        LMCreds                  = $LMCreds
        ADCreds                  = $ADCreds
        WorkerScript             = $InterimWorker
        Configuration            = $Configuration
        WorkerActivity           = "Shutting down machines; Stage $Stage"
        WorkerStatus             = 'Shutting down machines.'
        VMCreds                  = $VMCreds
    }
    Invoke-Parallelization @ShutdownParams

    $StageTable = $StageTable | Sort-Object -Property BootGroup, Name -CaseSensitive

    foreach ($BootGroup in $BootGroups) {
        Write-Host "Starting Boot Group $BootGroup."

        $BootingServers = $VMs | Where-Object { $_.Name -in (
                $StageTable | Where-Object { $_.BootGroup -ceq $BootGroup }).Name }

        # Boot Parameters
        $BootParams = @{
            Servers                  = $BootingServers
            RunspaceCreationActivity = "Creating Runspaces for stage $Stage, Group $BootGroup"
            LMCreds                  = $LMCreds
            ADCreds                  = $ADCreds
            WorkerScript             = $BootWorker
            Configuration            = $Configuration
            WorkerActivity           = "Booting machines; Stage $Stage, Group $BootGroup"
            WorkerStatus             = 'Booting machines.'
            VMCreds                  = $VMCreds
        }

        Invoke-Parallelization @BootParams

        # Update $VMTable Processed attribute to True if VM was successfully booted.
        foreach ($VM in $BootingServers) {
            $VMToUpdate = $VMTable | Where-Object { $_.Name -eq $VM.Name }
            if ($VM.Name -notin $Configuration.BootFailure -and $Configuration.Shutdown[$VM.Name]) {
                $VMToUpdate.Processed = $true
            }
        }

        $BootGroupFailures = $Configuration.BootFailure | Where-Object { $BootingServers.Name -eq $_ }

        # Check for Boot Failures
        if ($BootGroupFailures) {
            # Ask user if they want to continue
            $wshell = New-Object -ComObject Wscript.Shell
            $msg = "Unable to boot the following VMs: $BootGroupFailures. Continue script?"
            $ButtonClicked = $wshell.Popup($msg, 0, 'Boot Timeout Error', $Buttons.YesNo + $Icon.Question)
            if ($ButtonClicked -eq $Selection.No) {
                # Write new VM list with added Processed flag to CSV
                $newCSVFilename = "$CSVFilename.new"
                if (Test-Path -Path $newCSVFilename -PathType leaf) { Clear-Content -Path $newCSVFilename }
                $VMTable | Export-Csv -Path $newCSVFilename -NoTypeInformation -Force
                $Configuration.ScriptErrors += "$(Get-Date -Format G): User cancelled script."
                # Disconnect from vCenter
                Disconnect-VIServer -Server $Configuration.VIServer -Force -Confirm:$false

                # Write script errors to log file
                if (Test-Path -Path $ScriptErrors -PathType leaf) { Clear-Content -Path $ScriptErrors }
                Add-Content -Path $ScriptErrors -Value $Configuration.ScriptErrors

                Write-Host "$(Get-Date -Format G): Script error log saved to $ScriptErrors"

                # Inform user of path to service CSV to validate after restore
                Write-Host "$(Get-Date -Format G): Service list saved to $ScriptOutput"

                $wshell = New-Object -ComObject Wscript.Shell
                $elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
                $null = $wshell.Popup("Operation completed for $($Settings.TssFolder) in $elapsedMinutes minutes",
                    0, 'Done', $Buttons.OK + $Icon.Information)

                exit 1223
            }
        }
        Write-Host "Finished Boot Group $BootGroup."
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
$elapsedMinutes = $stopwatch.Elapsed.TotalMinutes
$stopwatch.Stop()
$Configuration.ScriptErrors += "$(Get-Date -Format G): Operation completed in $elapsedMinutes minutes."
Add-Content -Path $ScriptErrors -Value $Configuration.ScriptErrors

Write-Host "$(Get-Date -Format G): Script error log saved to $ScriptErrors"

# Deleting services CSV since script completed run
# Remove-Item -Path $ScriptOutput -Force

$wshell = New-Object -ComObject Wscript.Shell
$null = $wshell.Popup("Operation completed for $($Settings.TssFolder) in $elapsedMinutes minutes", 0, 'Done',
    $Buttons.OK + $Icon.Information)
#####END OF SCRIPT#######