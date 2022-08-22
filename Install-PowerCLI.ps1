#Requires -RunAsAdministrator
<#
.SYNOPSIS
    A script to automate the install of VMware PowerCLI.
.DESCRIPTION
    A script to automate the install of VMware PowerCLI. Generally it is best
    to call this script from another script to ensure PowerCLI commands are
    available.
.NOTES
    File Name  : Install-PowerCLI.ps1
    Author     : Dan Gill - dgill@gocloudwave.com
.LINK
    https://virtuallysober.com/2017/06/01/automatically-updating-to-powercli-6-5-1/
.LINK
    https://docs.microsoft.com/en-us/officeonlineserver/enable-tls-1-1-and-tls-1-2-support-in-office-online-server#enable-strong-cryptography-in-net-framework-45-or-higher
.INPUTS
    None. You cannot pipe objects to Install-PowerCLI.ps1.
.OUTPUTS
    None. Install-PowerCLI.ps1 does not generate output.
.EXAMPLE
    PS> .\Install-PowerCLI.ps1
.EXAMPLE
    PS> Invoke-Expression -Command "Install-PowerCLI.ps1"
#>

# Specify a directory to download and install the new PowerCLI module to for future offline access
$PSModulePath = $Env:SystemDrive + '\PowerCLIModule\'

#######################
# Testing if TLS 1.2 or above is enabled
#######################
if ([Net.ServicePointManager]::SecurityProtocol -notlike '*Tls1[23]*') {
    #######################
    # Set Strong Cryptography - https://docs.microsoft.com/en-us/officeonlineserver/enable-tls-1-1-and-tls-1-2-support-in-office-online-server#enable-strong-cryptography-in-net-framework-45-or-higher
    #######################
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Confirm:$false
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Confirm:$false
    #######################
    # Disable TLS 1.0 and 1.1
    #######################
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server') {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '1' -Type DWord -Force -Confirm:$false
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '0' -Type DWord -Force -Confirm:$false
    }
    #######################
    # Exit and ask user to re-run the script
    #######################
    Write-Warning 'This system did not have TLS 1.2 or above enabled. Please re-run the script so that the changes to enable TLS 1.2 and above take effect.'
    Exit
}

#######################
# Testing if PS Module path exists, if not creating it
#######################
$PSModulePathTest = Test-Path $PSModulePath
if ($PSModulePathTest -eq $False) {
    New-Item -ItemType Directory -Force -Path $PSModulePath
}
#######################
# Checking to see if PowerCLI is installed in Program Files, takes 5-30 seconds
#######################
Write-Progress -Id 1 -Activity 'Checking for PowerCLI' -CurrentOperation 'Checking if PowerCLI is installed in Program Files, wait 5-30 seconds'
$PowerCLIInstalled = Get-Package -ProviderName Programs -IncludeWindowsInstaller | `
    Where-Object { $_.Name -eq 'VMware vSphere PowerCLI' }
#######################
# If PowerCLI is installed then removing it, so we can run from the module instead
#######################
if ($PowerCLIInstalled) {
    Write-Progress -Id 2 -ParentId 1 -Activity 'PowerCLI in Program Files' `
        -CurrentOperation 'Uninstalling to allow for new PowerCLI module'
    # Uninstalling PS module
    try {
        $PowerCLIInstalled | Uninstall-Package -Force
    } catch {
        Write-Error -Message 'Uninstall Of PowerCLI Failed - Most likely due to not running as administrator' `
            -Category PermissionDenied

        Exit 1640
    }

    # Finished uninstall
    Write-Progress -Id 2 -ParentId 1 -Activity 'PowerCLI in Program Files' -Completed
}

Write-Progress -Id 1 -Activity 'Checking for PowerCLI' -Completed
#######################
# Checking to see if the NuGet Package Provider is already installed
#######################
$NuGetPackageProviderCheck = Get-PackageProvider -Name 'NuGet' -ListAvailable
#######################
# If NuGet Provider is not installed, nothing found, then running install...
#######################
if (!$NuGetPackageProviderCheck) {
    Write-Progress -Id 1 -Activity 'NuGet Package Provider' -CurrentOperation 'Not Found - Installing'
    # Trusting PS Gallery to remove prompt on install
    Set-PackageSource -Name 'PSGallery' -Trusted
    # Not installed, finding module online
    Find-PackageProvider -Name 'NuGet' -AllVersions
    # Installing module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
    Write-Progress -Id 1 -Activity 'NuGet Package Provider' -Completed
}
#######################
# Checking to see if the PowerCLI module is already installed
#######################
$PowerCLIModuleCheck = Get-Module -ListAvailable -Name 'VMware.PowerCLI'
#######################
# If PowerCLI module is not installed, nothing found, then running install...
#######################
if (!$PowerCLIModuleCheck) {
    Write-Progress -Id 1 -Activity 'PowerCLI Module' -CurrentOperation 'Not Found - Installing'
    # Trusting PS Gallery to remove prompt on install
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    # Not installed, finding module online
    Find-Module -Name 'VMware.PowerCLI'
    # Installing module
    Install-Module -Name 'VMware.PowerCLI' -Confirm:$false -AllowClobber -Force
    # If running this is a repeat demo/test, you can uninstall the module using the below:
    # Uninstall-Module -Name VMware.PowerCLI -Confirm:$false
    Write-Progress -Id 1 -Activity 'PowerCLI Module' -Completed
}
#######################
# Testing import of PowerCLI module
#######################
Write-Progress -Id 1 -Activity 'PowerCLI Module' -CurrentOperation 'Importing'
$null = Import-Module -Name 'VMware.PowerCLI'
Write-Progress -Id 1 -Activity 'PowerCLI Module' -Completed
Try {
    $null = Get-VICommand
    $PowerCLIImportTest = $True
} Catch {
    $PowerCLIImportTest = $False
} Finally {
    #######################
    # Outputting result
    #######################
    if ($PowerCLIImportTest) {
        Write-Information 'New PowerCLI Module Successfully Installed'
    } else {
        Write-Error -Message "Something went wrong! Maybe you, maybe me. Does this computer have internet access and did you run as administrator?`r`nTry installing PowerCLI in offline mode (Procedure 3): https://tinyurl.com/VMware-PowerCLI"
        Exit 22
    }
}