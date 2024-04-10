<#
.SYNOPSIS
    Header file to create user dialog box.
.DESCRIPTION
    A script to create a user dialog box. This script always runs from another
    script's call.
.NOTES
    File Name  : User-Prompts.ps1
    Author     : Dan Gill - dgill@gocloudwave.com
.INPUTS
    None. You cannot pipe objects to User-Prompts.ps1.
.OUTPUTS
    None. User-Prompts.ps1 does not generate output.
.EXAMPLE
    PS> .\User-Prompts.ps1
#>

<#
.SYNOPSIS
    Create user dialog box with single list item selection.
.DESCRIPTION
    Create user dialog box with single list item selection.
    Takes a Title, Message, List, and optional size parameters.
.PARAMETER Title
    Specifies the name of the dialog box.
.PARAMETER Prompt
    Specifies the message to prompt the user.
.PARAMETER Values
    Specifies an array to list for single selection.
.PARAMETER Width
    Specifies the width of the dialog box. Defaults to 300 pixels.
.PARAMETER Height
    Specifies the height of the dialog box. Defaults to 200 pixels.
.LINK
    https://docs.microsoft.com/en-us/powershell/scripting/samples/selecting-items-from-a-list-box?view=powershell-7.2
.INPUTS
    None. You cannot pipe objects to Select-SingleOptionDialogBoxx.
.OUTPUTS
    System.String. Select-SingleOptionDialogBoxx returns a string with the selected item.
.EXAMPLE
    PS> $SelectedItem = Select-SingleOptionDialogBoxx -Title 'Title' -Prompt 'Message' `
    -Values $SelectionList
.EXAMPLE
    PS> $SelectedItem = Select-SingleOptionDialogBoxx -Title 'Title' -Prompt 'Message' `
    -Values $SelectionList -Width 400
.EXAMPLE
    PS> $SelectedItem = Select-SingleOptionDialogBoxx -Title 'Title' -Prompt 'Message' `
    -Values $SelectionList -Height 400
.EXAMPLE
    PS> $SelectedItem = Select-SingleOptionDialogBoxx -Title 'Title' -Prompt 'Message' `
    -Values $SelectionList -Width 400 -Height 400
#>
function Select-SingleOptionDialogBox {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$Title,
        [Parameter(Mandatory)]
        [string[]]$Prompt,
        [Parameter(Mandatory)]
        [string[]]$Values,
        [Parameter(Mandatory = $false)]
        [Int]$Width = 300,
        [Parameter(Mandatory = $false)]
        [Int]$Height = 200
    )

    begin {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $buttonWidth = 75
        $buttonHeight = 23
        $buttonTopEdge = $Height - 80
        $OKbuttonLeftEdge = ( $Width / 2 ) - $buttonWidth
    }

    process {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = $Title
        $form.Size = New-Object System.Drawing.Size($Width, $Height)
        $form.StartPosition = 'CenterScreen'

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point($OKbuttonLeftEdge, $buttonTopEdge)
        $okButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point( ( $Width / 2 ), $buttonTopEdge)
        $cancelButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(($Width - 20), 20)
        $label.Text = $Prompt
        $form.Controls.Add($label)

        $listBox = New-Object System.Windows.Forms.ListBox
        $listBox.Location = New-Object System.Drawing.Point(10, 40)
        $listBox.Size = New-Object System.Drawing.Size(($Width - 40), 20)
        $listBox.Height = $Height - 120

        foreach ($value in $Values) { [void] $listBox.Items.Add($value) }

        $form.Controls.Add($listBox)

        $form.Topmost = $true

        $form.Add_Shown({ $listBox.Select() })

        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $SelectedItem = $listBox.SelectedItem

        } else {
            # Return null, determine what happens when user cancels in calling script
            $SelectedItem = $null
        }
    }

    end {
        return $SelectedItem
    }

}

function Enter-StringDialogBox {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$Title,
        [Parameter(Mandatory)]
        [string[]]$Prompt,
        [Parameter(Mandatory = $false)]
        [Int]$Width = 300,
        [Parameter(Mandatory = $false)]
        [Int]$Height = 200
    )

    begin {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $buttonWidth = 75
        $buttonHeight = 23
        $buttonTopEdge = $Height - 80
        $OKbuttonLeftEdge = ( $Width / 2 ) - $buttonWidth
    }

    process {
        $form = New-Object System.Windows.Forms.Form
        $form.Text = $Title
        $form.Size = New-Object System.Drawing.Size($Width, $Height)
        $form.StartPosition = 'CenterScreen'

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point($OKbuttonLeftEdge, $buttonTopEdge)
        $okButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point( ( $Width / 2 ), $buttonTopEdge)
        $cancelButton.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 20)
        $label.Size = New-Object System.Drawing.Size(($Width - 20), 20)
        $label.Text = $Prompt
        $form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 40)
        $textBox.Size = New-Object System.Drawing.Size(($Width - 40), 20)
        $form.Controls.Add($textBox)

        $form.Topmost = $true

        $form.Add_Shown({ $textBox.Select() })

        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $EnteredText = $textBox.Text

        } else {
            # Return null, determine what happens when user cancels in calling script
            $EnteredText = $null
        }
    }

    end {
        return $EnteredText
    }

}

function Get-FileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$initialDirectory,
        [Parameter(Mandatory)]
        [string[]]$title,
        [Parameter(Mandatory)]
        [string[]]$filter
    )

    [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.title = $title
    $OpenFileDialog.filter = $filter
    if ($OpenFileDialog.ShowDialog() -eq 'Cancel') {
        $wshell = New-Object -ComObject Wscript.Shell
        $null = $wshell.Popup('User canceled file selection. Exiting script.', 0, 'Exiting', `
                $Buttons.OK + $Icon.Exclamation)

        Exit 1223
    } else {
        return $OpenFileDialog.FileName
    }

}