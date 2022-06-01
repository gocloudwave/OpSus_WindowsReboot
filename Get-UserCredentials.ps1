function Get-UserCredentials {
  [CmdletBinding()]
  param (
    # Type of account
    [Parameter(Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      Position = 0)]
    [string]
    $Type,

    # Customer Name
    [Parameter(Mandatory = $true,
      ValueFromPipelineByPropertyName = $true,
      Position = 1)]
    [string]
    $Customer,

    # TSS Session used to connect to Thycotic API
    [Parameter(ValueFromPipelineByPropertyName = $true,
      Position = 2)]
    [Thycotic.PowerShell.Authentication.Session]
    $TssSession,

    # Thycotic Folder
    [Parameter(ValueFromPipelineByPropertyName = $true,
      Position = 3)]
    [Thycotic.PowerShell.Folders.Summary]
    $TssFolder,

    # Thycotic Secrets
    [Parameter(ValueFromPipelineByPropertyName = $true,
      Position = 4)]
    [System.Object[]]
    $TssRecords,

    # Secret selected by user from dialog box
    [Parameter(ValueFromPipelineByPropertyName = $true,
      Position = 5)]
    [string]
    $SecretName
  )

  begin {
    $Error.Clear()
    $Creds = $null
  }
  process {
    # If the user selected a Secret, obtain those credentials from Thycotic.
    if ( $SecretName ) {
      try {
        $Secret = $TssRecords | Where-Object { $_.SecretName -eq $SecretName } | Get-TssSecret -TssSession $TssSession -Comment 'Performing Site Discovery' -ErrorAction Stop
        $Creds = $Secret.GetCredential($null, 'username', 'password')
      } catch [System.Management.Automation.RuntimeException] {
        # Get-TssSecret broke during a recent upgrade to Thycotic. This workaround uses the slug method.
        try {
          # Fields are encapsulated by double-quotes using this method. Trim the quotes out.
          $SecretUsername = ($TssRecords | Where-Object { $_.SecretName -eq $SecretName } | Get-TssSecretField -TssSession $TssSession -Slug username).TrimStart('"').TrimEnd('"')
          $SecretPasswd = ($TssRecords | Where-Object { $_.SecretName -eq $SecretName } | Get-TssSecretField -TssSession $TssSession -Slug password).TrimStart('"').TrimEnd('"')
          $Creds = New-Object System.Management.Automation.PSCredential ($SecretUsername, (ConvertTo-SecureString $SecretPasswd -AsPlainText -Force))
          $Configuration.ScriptErrors += "WARNING: Runtime Exception; unable to retrieve $SecretName credentials using Get-TssSecret. Obtained using slug workaround. https://github.com/thycotic-ps/thycotic.secretserver/issues/258"
        } catch {
          while (!$Creds) {
            $Creds = Get-Credential -Message "Trouble reaching Thycotic. Please enter $SecretName credentials from $($TssFolder.folderName)."
          }
          $Configuration.ScriptErrors += 'ERROR: Unable to retrieve credentials. Prompted user to enter manually.'
          $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
          $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
          $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
        }
      } catch {
        while (!$Creds) {
          $Creds = Get-Credential -Message "Trouble reaching Thycotic. Please enter $SecretName credentials from $($TssFolder.folderName)."
        }
        $Configuration.ScriptErrors += 'ERROR: Unable to retrieve credentials. Prompted user to enter manually.'
        $Configuration.ScriptErrors += $Error[0].Exception.GetType().FullName
        $Configuration.ScriptErrors += "Error Message: $($_.Exception.Message)"
        $Configuration.ScriptErrors += "Error in Line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line)"
      }
    } else {
      while (!$Creds) {
        $Creds = Get-Credential -Message "User did not select credential to use. Please enter $Type credentials for $Customer."
      }
    }
  }
  end {
    return $Creds
  }
}