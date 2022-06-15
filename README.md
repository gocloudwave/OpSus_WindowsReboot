# Reboot Windows VMs with specified order

Takes a CSV file as input. Use a hypervisor to connect to Windows machines. Store Windows services details, issue
power-off command, wait until all systems are powered off, start systems based on priority from CSV, and ensure
services are back to their original state before moving to the next system.

## Table of Contents

- [Reboot Windows VMs with specified order](#reboot-windows-vms-with-specified-order)
  - [Table of Contents](#table-of-contents)
  - [Files](#files)
  - [Requirements](#requirements)
  - [Definitions](#definitions)
    - [MinimumPowerCLIVersion](#minimumpowercliversion)
    - [SecretTemplateLookup](#secrettemplatelookup)
    - [ssUri](#ssuri)
    - [DNSDomain](#dnsdomain)
    - [InvalidCertAction](#invalidcertaction)
    - [vCenter](#vcenter)
    - [TssFolder](#tssfolder)
  - [Restart Windows VMs](#restart-windows-vms)

## Files

- Get-UserCredentials.ps1
  - Contains a function to create a PS Credential from Thycotic or user prompts.
- Get-VMToolsStatus.ps1
  - Contains a function to check the VMware tools status.
- Install-PowerCLI.ps1
  - Can be run standalone, as an Administrator, or can be called by Restart-Windows.ps1 to configure
    the server to run PowerCLI commands.
- Restart-Windows.ps1
  - Run this script to restart VMs.
- Search-TssFolders.ps1
  - Extends functionality of Search-TssFolder from the Thycotic.SecretServer Module.
- settings.json
  - Contains settings configuration data.
- User-Prompts.ps1
  - Used to create dialog boxes for user input.

## Requirements

1. Run `Restart-Windows.ps1` from a server on the same domain that vCenter uses for authentication.
2. Create `settings.json` file in script directory.

   **Example**

   ```json
   {
     "MinimumPowerCLIVersion": "12.4.1.18769701",
     "SecretTemplateLookup": {
       "ActiveDirectoryAccount": 6001,
       "LocalUserWindowsAccount": 6003
     },
     "ssUri": "https://domain.secretservercloud.com",
     "DNSDomain": "FABRIKAM.COM",
     "InvalidCertAction": "Ignore",
     "vCenter": "vcenter.domain.local",
     "TssFolder": "FolderA"
   }
   ```

3. Create a CSV file listing the VM Names to process and the order for processing. The file must have at least two
   columns (Name and BootGroup) with a header row. The file may contain an additional column (ShutdownGroup) if the
   shutdown order matters.

   **Example 1**

   ```
   Name,BootGroup
   ServerA,1
   ServerB,1
   ServerC,2
   ServerD,3
   ```

   **Example 2**

   ```
   Name,BootGroup,ShutdownGroup
   ServerA,1,3
   ServerB,1,3
   ServerC,2,2
   ServerD,3,1
   ```

## Definitions

### MinimumPowerCLIVersion

Set this to the minimum tested PowerCLI version this script needs to run successfully.

### SecretTemplateLookup

Hashtable that maps the SecretTemplateId to an `ActiveDirectoryAccount` or a `LocalUserWindowsAccount`.

### ssUri

SecretServer URI used for API calls to Thycotic.

### DNSDomain

What domain must the server running the script belong to? This ensures the server can communciate with the vCenter
server.

### InvalidCertAction

Define the action to take when an attempted connection to a server fails due to a certificate error. For more
information about invalid certificates, run 'Get-Help about_invalid_certificates'.

### vCenter

The vCenter that can manage the specified VMs.

### TssFolder

The name of the top-level folder in Thycotic that contains the secrets.

## Restart Windows VMs

1. Place `Get-UserCredentials.ps1`, `Get-VMToolsStatus.ps1`, `Install-PowerCLI.ps1`, `Restart-Windows.ps1`,
   `Search-TssFolders.ps1`, `settings.json`, and `User-Prompts.ps1` in a single folder on a machine that can
   connect to the vCenter server.
2. Run `Restart-Windows.ps1`.
   - If the script fails to configure PowerCLI, run `Install-PowerCLI.ps1` manually as an Administrator.
3. The script will prompt the user for a CSV file listing VM Names, BootGroup, and (optionally) ShutdownGroup.
4. Enter credentials needed to connect to Thycotic.
   - If the user enters incorrect credentials twice, the script will skip connecting to Thycotic.
   - If Thycotic is down, the script will prompt the user to enter AD and Local Machine Administrator credentials
     manually.
5. Select the secret name for the AD user.
   - Cancel later prompts the user to manually enter the credentials.
6. Select the secret name for the Local Machine Administrator user.
   - Cancel later prompts the user to manually enter the credentials.
7. If no secrets exist with the Active Directory or Local Windows templates, the script will prompt the user to
   enter the credentials manually.
8. The script will output its actions to the screen while it runs.
9. The script will display a `Done` dialog box when it completes that states how long the script took to run.
