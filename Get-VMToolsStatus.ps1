function Get-VMToolsStatus {
    <#
    .SYNOPSIS
        This will check the status of the VMware vmtools status.
        Properties include Name, Status, UpgradeStatus and Version

    .NOTES
        Name: Get-VMToolsStatus
        Author: theSysadminChannel
        Version: 1.0
        DateCreated: 2020-Sep-1

    .LINK
        https://thesysadminchannel.com/powercli-check-vmware-tools-status/ -

    .EXAMPLE
        Please refer to the -Online version
        help Get-VMToolsStatus -Online

    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Position = 0,
            ParameterSetName = 'NonPipeline'
        )]
        [Alias('VM', 'ComputerName', 'VMName')]
        [string[]]  $Name,


        [Parameter(
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Pipeline'
        )]
        [PSObject[]]  $InputObject
    )

    begin {
        if (-not $Global:DefaultVIServer) {
            Write-Error 'Unable to continue.  Please connect to a vCenter Server.' -ErrorAction Stop
        }

        #Verifying the object is a VM
        if ($PSBoundParameters.ContainsKey('Name')) {
            $InputObject = Get-VM $Name
        }

        $i = 1
        $Count = $InputObject.Count
    }

    process {
        if (($null -eq $InputObject.VMHost) -and ($null -eq $InputObject.MemoryGB)) {
            Write-Error 'Invalid data type. A virtual machine object was not found' -ErrorAction Stop
        }

        foreach ($Object in $InputObject) {
            $Error.Clear()
            try {
                [PSCustomObject]@{
                    Name          = $Object.name
                    Status        = $Object.ExtensionData.Guest.toolsRunningStatus
                    UpgradeStatus = $Object.ExtensionData.Guest.toolsVersionStatus2
                    Version       = $Object.ExtensionData.Guest.toolsVersion
                }
            } catch {
                Write-Error $_.Exception.Message

            } finally {
                if ($PSBoundParameters.ContainsKey('Name')) {
                    $PercentComplete = ($i / $Count).ToString('P')
                    Write-Progress -Id 1 -Activity "Processing VM: $($Object.Name)" -Status "$i/$count : $PercentComplete Complete" -PercentComplete $PercentComplete.Replace('%', '')
                    $i++
                } else {
                    Write-Progress -Id 1 -Activity "Processing VM: $($Object.Name)" -Status "Completed: $i"
                    $i++
                }
                $Error.Clear()
            }
        }
        Write-Progress -Id 1 -Activity 'Processing VM Tools' -Completed
    }

    end {}
}