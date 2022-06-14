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

# Prompt user for CSV with VMs, BootGroup, and (optionally) ShutdownGroup
[System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null

$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.initialDirectory = $PSScriptRoot
$OpenFileDialog.title = 'Select CSV file with VM names and processing order'
$OpenFileDialog.filter = 'Comma-delimited files (*.csv)|*.csv'
if ($OpenFileDialog.ShowDialog() -eq 'Cancel') {
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup('User canceled file selection. Exiting script.', 0, 'Exiting', $Buttons.OK + $Icon.Exclamation)

    Exit 1233
}

$VMTable = Import-Csv -Path "$($OpenFileDialog.filename)"

# Check for ShutdownGroup column, if it doesn't exist shutdown order doesn't matter set all to 1
if (![bool]($VMTable | Get-Member -Name ShutdownGroup)) {
    $VMTable | Add-Member -MemberType NoteProperty -Name 'ShutdownGroup' -Value '1'
}

$BootGroups = $VMTable.BootGroup | Sort-Object -Unique -CaseSensitive
$ShutdownGroups = $VMTable.ShutdownGroup | Sort-Object -Unique -CaseSensitive

$ADCreds = $null
$LMCreds = $null

$VMCreds = @{}
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
$Configuration.Shutdown = @{}
$Configuration.VIServer = $null

# Base path to Secret Server
$ssUri = $Settings.ssUri

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

# Install Thycotic.SecretServer PowerShell module if not installed
if (!(Get-Module -ListAvailable -Name Thycotic.SecretServer)) {
    if ( ( Get-PSRepository -Name 'PSGallery' ).InstallationPolicy -ne 'Trusted' ) {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    }
    Install-Module -Name Thycotic.SecretServer -Confirm:$false -AllowClobber -Force
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

$VMs = Get-VM -Name $VMTable.Name -Server $Configuration.VIServer

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
    if ($Session) { $null = Close-TssSession -TssSession $Session }
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
                $ErrorMessage = "SHUTDOWN WARNING: The credentials for $($VMcreds.Username) do not work " + `
                    "on $($VM.Name). If this is a one-off error, please correct the credentials on the server." + `
                    ' If this error repeats often, update the credentials in Thycotic. Service collection failed.'
                $Configuration.ScriptErrors += $ErrorMessage
                $Configuration.Shutdown[$VM.Name] = $false
            } else {
                # Convert multiline string to array of strings
                try {
                    $Services = (($TestAccess.ScriptOutput).Trim()).Split("`n")
                    foreach ($Service in $Services) {
                        $Configuration.Services += New-Object PSObject `
                            -Property @{ VM = $VM.Name; ServiceName = $Service.Trim() }
                    }
                    Write-Host "$(Get-Date -Format G): Collected services for $($VM.Name)."
                } catch [System.Management.Automation.RuntimeException] {
                    $Configuration.ScriptErrors += "SHUTDOWN WARNING: Get-Service returned NULL on $($VM.Name)."
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
            $ErrorMessage = "SHUTDOWN WARNING: The credentials for $($VMcreds.Username) do not work on " +
            "$($VM.Name). If this is a one-off error, please correct the credentials on the server. If this " +
            'error repeats often, then update the credentials in Thycotic.'
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.Shutdown[$VM.Name] = $false
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
            $Configuration.ScriptErrors += "SHUTDOWN WARNING: Invalid argument processing $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
            $ErrorMessage = "Parameters: Server - $($Configuration.VIServer), VM - $($VM.Name), " +
            "GuestCredential - $($VMcreds.Username)"
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.Shutdown[$VM.Name] = $false
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException], `
            [System.InvalidOperationException] {
            $Configuration.ScriptErrors += "SHUTDOWN WARNING: Failure connecting to $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.Shutdown[$VM.Name] = $false
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
            $ErrorMessage = "SHUTDOWN WARNING: Unable to process $($VM.Name). Check the VM to ensure it " +
            'is working properly. Error message and attempted command below:'
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.Shutdown[$VM.Name] = $false
        } catch {
            $Configuration.ScriptErrors += "SHUTDOWN WARNING: Other error processing $($VM.Name)."
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

$VMTable = $VMTable | Sort-Object -Property ShutdownGroup, Name -CaseSensitive

foreach ($group in $ShutdownGroups) {
    $GroupMembers = $VMTable | Where-Object { $_.ShutdownGroup -ceq $group }
    $GroupCount = $GroupMembers.Count
    $VMGroup = $VMs | Where-Object { $GroupMembers.Name -eq $_.Name }

    # Process no more than 25% of the list at once. (Minimum value = 20)
    $MaxRunspaces = [Math]::Max([Math]::Ceiling($GroupCount / 4), 20)

    # Create runspace pool for parralelization
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
    $RunspacePool.Open()

    $Jobs = New-Object System.Collections.ArrayList

    # Display progress bar
    Write-Progress -Id 1 -Activity "Creating Runspaces for group $group" `
        -Status "Creating runspaces for $GroupCount VMs." -PercentComplete 0

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

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
        $RSPercentComplete = ($VMindex / $GroupCount ).ToString('P')
        $Activity = "Runspace creation: Processing $VM, Group $group"
        $Status = "$VMindex/$GroupCount : $RSPercentComplete Complete"
        $CleanPercent = $RSPercentComplete.Replace('%', '')
        Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $CleanPercent

        $VMindex++
    }

    Write-Progress -Id 1 -Activity "Runspace creation for group $group" -Completed

    # Used to determine percentage completed.
    $TotalJobs = $Jobs.Runspace.Count

    Write-Progress -Id 2 -Activity "Collect services; Group $group" -Status 'Collecting services.' `
        -PercentComplete 0

    # Update percentage complete and wait until all jobs are finished.
    while ($Jobs.Runspace.IsCompleted -contains $false) {
        $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
        $PercentComplete = ($CompletedJobs / $TotalJobs ).ToString('P')
        $Status = "$CompletedJobs/$TotalJobs : $PercentComplete Complete"
        Write-Progress -Id 2 -Activity "Collect services; Group $group" -Status $Status `
            -PercentComplete $PercentComplete.Replace('%', '')
        Start-Sleep -Milliseconds 100
    }

    # Clean up runspace.
    $RunspacePool.Close()

    Write-Progress -Id 2 -Activity "Collect services; Group $group" -Completed
}

# Write services data to CSV. If manual intervention is needed, user can access this file to check services.
if (Test-Path -Path $ScriptOutput -PathType leaf) { Clear-Content -Path $ScriptOutput }
$Configuration.Services | Export-Csv -Path $ScriptOutput -NoTypeInformation -Force

Write-Host "$(Get-Date -Format G): Services list saved to $ScriptOutput"

$VMs = Get-VM -Name $VMTable.Name -Server $Configuration.VIServer
$VMCount = $VMs.Count

Write-Progress -Id 2 -Activity 'Shutdown' -Status 'Waiting for shutdown.' -PercentComplete 0

while ($VMs.PowerState -contains 'PoweredOn') {
    $VMsShutdown = ($VMs.PowerState -eq 'PoweredOff').Count
    $PercentComplete = ($VMsShutdown / $VMCount).ToString('P')
    $Status = "$VMsShutdown/$VMCount : $PercentComplete Complete"
    Write-Progress -Id 2 -Activity 'Shutdown' -Status $Status `
        -PercentComplete $PercentComplete.Replace('%', '')
    Start-Sleep -Milliseconds 1000
    $VMs = Get-VM -Name $VMTable.Name -Server $Configuration.VIServer
}

Write-Progress -Id 2 -Activity 'Shutdown' -Completed

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

        # Parameter help description
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ServiceName,

        # Hash table for configuration data
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Configuration
    )

    begin {
        $Error.Clear()
        # Run two Powershell commands with one Invoke-VMScript.
        # Get service status for all services in ServicesList and use while loop to wait until all services are
        # running.
        $ScriptText = "try { while ((Get-Service -Name '$ServiceName' -ErrorAction Stop).Status -ne 'Running') " +
        '{ Start-Sleep -Seconds 1 } } catch { Write-Warning "Access denied" }'
    }

    process {
        try {
            # Wait for VM power state ON and DNS Name assignment
            while (($VM.PowerState -ne 'PoweredOn') -or (![bool]$VM.Guest.HostName)) {
                $VM = Get-VM -Name $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference
                # Give the machine time before attempting login after boot up
                Start-Sleep -Seconds 30
            }

            # Run script to check services.
            Write-Host "$(Get-Date -Format G): Checking '$ServiceName' service status on $($VM.Name)."
            $TestAccess = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null

            while ($TestAccess.ScriptOutput -like 'WARNING: Access denied*') {
                Write-Host "$(Get-Date -Format G): $($VM.Name) failed login. Waiting 60 seconds and trying again."
                Start-Sleep -Seconds 60

                # Run script to check services.
                $TestAccess = Invoke-VMScript -Server $Configuration.VIServer -VM $VM -ScriptText $ScriptText `
                    -GuestCredential $VMcreds -ErrorAction $ErrorActionPreference 3> $null
            }

            Write-Host "$(Get-Date -Format G): '$ServiceName' service is running on $($VM.Name)."

        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidGuestLogin] {
            $ErrorMessage = "BOOT WARNING: The credentials for $($VMcreds.Username) do not work on ' +
            '$($VM.Name). If this is a one-off error, please correct the credentials on the server. If this " +
            'error repeats often, then update the credentials in Thycotic.'
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [VMware.VimAutomation.ViCore.Types.V1.ErrorHandling.InvalidArgument] {
            $Configuration.ScriptErrors += "BOOT WARNING: Invalid argument processing $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
            $ErrorMessage = "Parameters: Server - $($Configuration.VIServer), VM - $($VM.Name), ' +
            'GuestCredential - $($VMcreds.Username)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.ViServerConnectionException], `
            [System.InvalidOperationException] {
            $Configuration.ScriptErrors += "BOOT WARNING: Failure connecting to $($VM.Name)."
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
            $ErrorMessage = "BOOT WARNING: Unable to process $($VM.Name). Check the VM to ensure it " +
            'is working properly. Error message and attempted command below:'
            $Configuration.ScriptErrors += $ErrorMessage
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } catch {
            $Configuration.ScriptErrors += "BOOT WARNING: Other error processing $($VM.Name)."
            $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
            $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
            $ErrorMessage = "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
            $Configuration.ScriptErrors += $ErrorMessage
        } finally {
            $Error.Clear()
        }
    }
}

$VMTable = $VMTable | Sort-Object -Property BootGroup, Name -CaseSensitive

foreach ($group in $BootGroups) {
    $GroupMembers = $VMTable | Where-Object { $_.BootGroup -ceq $group }
    $ServiceCount = ($Configuration.Services | Where-Object { $GroupMembers.Name -eq $_.VM }).Count
    $VMGroup = $VMs | Where-Object { $GroupMembers.Name -eq $_.Name }

    # Process no more than 25% of the list at once. (Minimum value = 20)
    $MaxRunspaces = [Math]::Max([Math]::Ceiling($ServiceCount / 4), 20)

    # Create runspace pool for parralelization
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $SessionState, $Host)
    $RunspacePool.Open()

    $Jobs = New-Object System.Collections.ArrayList

    # Display progress bar
    Write-Progress -Id 1 -Activity "Creating Runspaces for group $group" `
        -Status "Creating runspaces for $ServicepCount VMs." -PercentComplete 0

    $ServiceIdx = 1
    # Create job for each VM
    foreach ($VM in $VMGroup) {
        if ($Configuration.Shutdown[$VM.Name]) {
            # Using previously calculated credentials from shutdown job.
            $Creds = $VMCreds[$VM.Name]
            Write-Host "$(Get-Date -Format G): Starting $($VM.Name)."
            $VM = Start-VM -VM $VM -Server $Configuration.VIServer -ErrorAction $ErrorActionPreference

            $ServicesList = $Configuration.Services | Where-Object { $_.VM -eq $VM.Name }

            foreach ($service in $ServicesList.ServiceName) {

                $PowerShell = [powershell]::Create()
                $PowerShell.RunspacePool = $RunspacePool
                $null = $PowerShell.AddScript($BootWorker).AddArgument($VM).AddArgument($Creds).AddArgument($service).AddArgument($Configuration)

                $JobObj = New-Object -TypeName PSObject -Property @{
                    Runspace   = $PowerShell.BeginInvoke()
                    PowerShell = $PowerShell
                }

                $null = $Jobs.Add($JobObj)
                $RSPercentComplete = ($ServiceIdx / $ServiceCount ).ToString('P')
                $Activity = "Runspace creation for bootup: Processing $service on $VM, Group $group"
                $Status = "$ServiceIdx/$ServiceCount : $RSPercentComplete Complete"
                $CleanPercent = $RSPercentComplete.Replace('%', '')
                Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $CleanPercent

                $ServiceIdx++
            }
        } else {
            Write-Host "Skipping $($VM.Name) because it failed during shutdown phase."
        }
    }

    Write-Progress -Id 1 -Activity "Runspace creation for group $group" -Completed

    # Used to determine percentage completed.
    $TotalJobs = $Jobs.Runspace.Count

    Write-Progress -Id 2 -Activity 'Booting' -Status 'Booting machines.' -PercentComplete 0

    # Update percentage complete and wait until all jobs are finished.
    while ($Jobs.Runspace.IsCompleted -contains $false) {
        $CompletedJobs = ($Jobs.Runspace.IsCompleted -eq $true).Count
        $PercentComplete = ($CompletedJobs / $TotalJobs ).ToString('P')
        $Status = "$CompletedJobs/$TotalJobs : $PercentComplete Complete"
        Write-Progress -Id 2 -Activity "Booting machines; Group $group" -Status $Status `
            -PercentComplete $PercentComplete.Replace('%', '')
        Start-Sleep -Milliseconds 100
    }

    # Clean up runspace.
    $RunspacePool.Close()

    Write-Progress -Id 2 -Activity 'Booting machines' -Completed
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