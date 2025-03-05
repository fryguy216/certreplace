#Requires -Modules @{ModuleName='WindowsForms';ModuleVersion='5.0.0'}
#Requires -Modules @{ModuleName='System.Security.Cryptography.X509Certificates'}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security.Cryptography

# Main Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Keystore and P7B Certificate Viewer"
$form.Size = New-Object System.Drawing.Size(1200, 700)
$form.StartPosition = "CenterScreen"

# Open Keystore Button
$openKeystoreButton = New-Object System.Windows.Forms.Button
$openKeystoreButton.Location = New-Object System.Drawing.Point(10, 10)
$openKeystoreButton.Size = New-Object System.Drawing.Size(120, 30)
$openKeystoreButton.Text = "Open Keystore"
$form.Controls.Add($openKeystoreButton)

# Keystore Path Label
$keystorePathLabel = New-Object System.Windows.Forms.Label
$keystorePathLabel.Location = New-Object System.Drawing.Point(140, 15)
$keystorePathLabel.Size = New-Object System.Drawing.Size(400, 20)
$form.Controls.Add($keystorePathLabel)

# Keystore Certificate Listbox
$keystoreCertificateListBox = New-Object System.Windows.Forms.ListBox
$keystoreCertificateListBox.Location = New-Object System.Drawing.Point(10, 50)
$keystoreCertificateListBox.Size = New-Object System.Drawing.Size(580, 500)
$form.Controls.Add($keystoreCertificateListBox)

# Open P7B Button
$openP7BButton = New-Object System.Windows.Forms.Button
$openP7BButton.Location = New-Object System.Drawing.Point(600, 10)
$openP7BButton.Size = New-Object System.Drawing.Size(120, 30)
$openP7BButton.Text = "Open P7B"
$form.Controls.Add($openP7BButton)

# P7B Path Label
$p7bPathLabel = New-Object System.Windows.Forms.Label
$p7bPathLabel.Location = New-Object System.Drawing.Point(730, 15)
$p7bPathLabel.Size = New-Object System.Drawing.Size(400, 20)
$form.Controls.Add($p7bPathLabel)

# P7B Certificate Listbox
$p7bCertificateListBox = New-Object System.Windows.Forms.ListBox
$p7bCertificateListBox.Location = New-Object System.Drawing.Point(600, 50)
$p7bCertificateListBox.Size = New-Object System.Drawing.Size(580, 500)
$form.Controls.Add($p7bCertificateListBox)

# Replace Button
$replaceButton = New-Object System.Windows.Forms.Button
$replaceButton.Location = New-Object System.Drawing.Point(10, 560)
$replaceButton.Size = New-Object System.Drawing.Size(150, 30)
$replaceButton.Text = "Replace Selected"
$replaceButton.Enabled = $false
$form.Controls.Add($replaceButton)

# Open File Dialogs
$openKeystoreFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openKeystoreFileDialog.Filter = "Keystore Files (*.p12;*.pfx)|*.p12;*.pfx|All files (*.*)|*.*"
$openKeystoreFileDialog.Title = "Select Keystore File"

$openP7BFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$openP7BFileDialog.Filter = "P7B Files (*.p7b)|*.p7b|All files (*.*)|*.*"
$openP7BFileDialog.Title = "Select P7B File"

# Keystore Variables
$keystoreCollection = $null
$keystorePath = ""
$p7bCollection = $null
$p7bPath = ""

# Open Keystore Button Click Event
$openKeystoreButton.Add_Click({
    if ($openKeystoreFileDialog.ShowDialog() -eq "OK") {
        $keystorePath = $openKeystoreFileDialog.FileName
        $keystorePathLabel.Text = $keystorePath
        $keystoreCertificateListBox.Items.Clear()

        try {
            # Prompt for Password
            $passwordForm = New-Object System.Windows.Forms.Form
            $passwordForm.Text = "Enter Keystore Password"
            $passwordForm.Size = New-Object System.Drawing.Size(300, 150)
            $passwordForm.StartPosition = "CenterScreen"
            $passwordForm.FormBorderStyle = "FixedDialog"
            $passwordForm.MaximizeBox = $false
            $passwordForm.MinimizeBox = $false

            $passwordLabel = New-Object System.Windows.Forms.Label
            $passwordLabel.Location = New-Object System.Drawing.Point(10, 20)
            $passwordLabel.Text = "Password:"
            $passwordForm.Controls.Add($passwordLabel)

            $passwordTextBox = New-Object System.Windows.Forms.TextBox
            $passwordTextBox.Location = New-Object System.Drawing.Point(80, 20)
            $passwordTextBox.Size = New-Object System.Drawing.Size(200, 20)
            $passwordTextBox.PasswordChar = '*'
            $passwordForm.Controls.Add($passwordTextBox)

            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(110, 80)
            $okButton.Size = New-Object System.Drawing.Size(80, 30)
            $okButton.Text = "OK"
            $passwordForm.Controls.Add($okButton)

            $passwordForm.Add_Shown({$passwordForm.Activate()})

            $okButton.Add_Click({
                $passwordForm.DialogResult = "OK"
                $passwordForm.Close()
            })

            if ($passwordForm.ShowDialog() -eq "OK") {
                $password = $passwordTextBox.Text

                $keystoreCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                try{
                    $keystoreCollection.Import($keystorePath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

                    foreach ($cert in $keystoreCollection) {
                        $keystoreCertificateListBox.Items.Add($cert.Subject)
                    }
                }
                catch{
                  [System.Windows.Forms.MessageBox]::Show("Invalid Password or Keystore", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }

        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error opening keystore: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    $replaceButton.Enabled = ($keystoreCollection -ne $null) -and ($p7bCollection -ne $null)
})

# Open P7B Button Click Event
$openP7BButton.Add_Click({
    if ($openP7BFileDialog.ShowDialog() -eq "OK") {
        $p7bPath = $openP7BFileDialog.FileName
        $p7bPathLabel.Text = $p7bPath
        $p7bCertificateListBox.Items.Clear()

        try {
            $p7bCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $p7bCollection.Import($p7bPath)

            foreach ($cert in $p7bCollection) {
                $p7bCertificateListBox.Items.Add($cert.Subject)
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    $replaceButton.Enabled = ($keystoreCollection -ne $null) -and ($p7bCollection -ne $null)
})

# Replace Button Click Event
$replaceButton.Add_Click({
    $keystoreCertSubject = $keystoreCertificateListBox.SelectedItem
    $p7bCertSubject = $p7bCertificateListBox.SelectedItem

    $keystoreCert = $keystoreCollection | Where-Object {$_.Subject -eq $keystoreCertSubject}
    $p7bCert = $p7bCollection | Where-Object {$_.Subject -eq $p7bCertSubject}

    if ($keystoreCert -and $p7bCert) {
        $keystoreCollection.Remove($keystoreCert)
        $keystoreCollection.Add($p7bCert)

        $keystoreCertificateListBox.Items.Remove($keystoreCertSubject)
        $keystoreCertificateListBox.Items.Add($p7bCertSubject)

        # Update the keystore file (requires password)
        $keystoreCollection.Export($keystorePath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

        [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

$form.Add_Shown({$form.Activate()})
$form.ShowDialog()
