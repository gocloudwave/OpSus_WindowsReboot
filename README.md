# Reboot Windows VMs with specified order

Use a hypervisor to connect to Windows machines.
Store Windows services details, issue power-off command, wait until all systems
are powered off, start systems based on priority from VMware tagging, and ensure services
are back to their original state before moving to the next system. The script
will shutdown all servers within a stage before booting the servers up again.
_NOTE: Current script only supports VMware._

## Table of Contents

- [Reboot Windows VMs with specified order](#reboot-windows-vms-with-specified-order)
  - [Table of Contents](#table-of-contents)
  - [Files](#files)
  - [Requirements](#requirements)
  - [Definitions](#definitions)
    - [Customer](#customer)
    - [DNSDomain](#dnsdomain)
    - [InvalidCertAction](#invalidcertaction)
    - [MinsBtwStages](#minsbtwstages)
    - [BootTimeout](#boottimeout)
    - [ShutdownTimeout](#shutdowntimeout)
    - [vCenter](#vcenter)
    - [TssFolder](#tssfolder)
    - [TssDomain](#tssdomain)
    - [TssUser](#tssuser)
    - [SecretTemplateLookup](#secrettemplatelookup)
    - [ssUri](#ssuri)
    - [SvcWhitelist](#svcwhitelist)
  - [Restart Windows VMs](#restart-windows-vms)

## Files

- Get-UserCredentials.ps1
  - Contains a function to create a PS Credential from Thycotic or user prompts.
- Restart-Windows.ps1
  - Run this script to restart VMs.
- Search-TssFolders.ps1
  - Extends functionality of Search-TssFolder from the Thycotic.SecretServer
    Module.
- settings.json
  - Contains settings configuration data.
- User-Prompts.ps1
  - Used to create dialog boxes for user input.

## Requirements

1. You must have [.NET Framework version 4.7.2 or higher](https://dotnet.microsoft.com/en-us/download/dotnet-framework)
   to run this script.
2. You must have PowerShell 5.1.
3. You must [install PowerShell module VMware.PowerCLI](https://www.powershellgallery.com/packages/VMware.PowerCLI)
   version 13.1.0.21624340 or above.
4. You must [install PowerShell module Thycotic.SecretServer version 0.61.0](https://www.powershellgallery.com/packages/Thycotic.SecretServer/0.61.0)
   (this is the final version that supports PowerShell 5.1)
   1. You will need to modify Search-TssSecret.ps1 line 274 as mentioned
      [here](https://github.com/thycotic-ps/thycotic.secretserver/issues/350#issuecomment-1609828582).
5. Run `Restart-Windows.ps1` from a server on the same domain that vCenter uses
   for authentication.
   - The user must have the follwing permissions in vCenter:
     - Virtual Machine
       - Guest Operations
         - Guest operation modifications
         - Guest operation program execution
         - Guest operation queries
       - Interaction
         - Console interaction
         - Power off
         - Power on
   - The user also must have permission to add/update PowerShell modules on the
     system where the script will run.
6. Create `settings.json` file in script directory. **Note: You may use any
   name, but it must be a JSON file.**

   **Example**

   ```json
   {
     "Customer": "MMM",
     "vCenter": "vcenter.fabrikam.local",
     "TssFolder": "ThycoticFolder",
     "TssDomain": "ThycoticDomain",
     "TssUser": "ThycoticUser",
     "DNSDomain": "fabrikam.LOCAL",
     "MinsBtwStages": 15,
     "BootTimeout": 5,
     "ShutdownTimeout": 30,
     "InvalidCertAction": "Ignore",
     "SecretTemplateLookup": {
       "ActiveDirectoryAccount": 6001,
       "LocalUserWindowsAccount": 6003
     },
     "ssUri": "https://fabrikam.secretservercloud.com",
     "SvcWhitelist": ["Array*", "*of*", "*services", "to", "*check*"]
   }
   ```

7. Tag all VMs using categories Customer, CC+ Process, CC+ Stage, CC+ Boot
   Group, CC+ Shutdown Group

## Definitions

### Customer

Customer name as tagged using Customer category in VMware.

### DNSDomain

What domain must the server running the script belong to? This ensures the
server can communciate with the vCenter server.

### InvalidCertAction

Define the action to take when an attempted connection to a server fails due to
a certificate error. For more information about invalid certificates, run
`Get-Help about_invalid_certificates`.

### MinsBtwStages

How many minutes should the script wait after completing one stage before
beginning the next stage.

### BootTimeout

How many minutes should the script wait before considering a server boot as
failed. The user will see a prompt to indicate the failed servers.

### ShutdownTimeout

How many minutes should the script wait before considering a server shutdown as
failed. The script will remove that server from furhter processing until the final reboot.

### vCenter

vCenter to connect to.

### TssFolder

The name of the folder within Thycotic that contains the credentials needed.

### TssDomain

The domain needed for authentication to Thycotic. **Changeable when entering credentials**

### TssUser

The user authenticating to Thycotic. **Changeable when entering credentials**

### SecretTemplateLookup

Hash table that maps the SecretTemplateId to an `ActiveDirectoryAccount` or a
`LocalUserWindowsAccount`.

### ssUri

SecretServer URI used for API calls to Thycotic.

### SvcWhitelist

An array of services to check for during the shutdown phase of the script. If
the service exists on the server, is set to Automatic, and is Running, then the
script will ensure the same state upon boot. Wildcards are permitted.

## Restart Windows VMs

1. Place `Get-UserCredentials.ps1`, `Restart-Windows.ps1`, `Search-TssFolders.ps1`,
   `settings.json`, and `User-Prompts.ps1` in a single folder on a machine that
   can connect to the vCenter server.
   - If you downloaded the scripts from the Internet, you need to ensure that
     the files are unblocked. You can ublock them via the PowerShell command:
     `Get-ChildItem {PATH TO DOWNLOADED FILES} | Unblock-File`.
2. Run `Restart-Windows.ps1`.
3. The script will prompt the user for the settings.json file location.
   - This is useful if you want to have a settings file for each customer.
4. Enter credentials needed to connect to Thycotic.
   - If the user enters incorrect credentials twice, the script will skip
     connecting to Thycotic.
   - If Thycotic is down, the script will prompt the user to enter AD and Local
     Machine Administrator credentials manually.
5. Select the secret name for the AD user.
   - Cancel later prompts the user to manually enter the credentials.
6. Select the secret name for the Local Machine Administrator user.
   - Cancel later prompts the user to manually enter the credentials.
7. If no secrets exist with the Active Directory or Local Windows templates, the
   script will prompt the user to enter the credentials manually.
8. The script will output its actions to the screen while it runs.
   - The script will list servers and services waiting to start at every five
     minute mark. The end user must take action to start the services manually
     if the user feels too much time has passed, then the script will continue
     as planned.
9. The script will display a `Done` dialog box when it completes that states
   how long the script took to run.
