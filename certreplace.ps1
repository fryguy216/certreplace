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

# Keystore Certificate DataGridView
$keystoreCertificateDataGridView = New-Object System.Windows.Forms.DataGridView
$keystoreCertificateDataGridView.Location = New-Object System.Drawing.Point(10, 50)
$keystoreCertificateDataGridView.Size = New-Object System.Drawing.Size(580, 500)
$form.Controls.Add($keystoreCertificateDataGridView)

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

# P7B Certificate DataGridView
$p7bCertificateDataGridView = New-Object System.Windows.Forms.DataGridView
$p7bCertificateDataGridView.Location = New-Object System.Drawing.Point(600, 50)
$p7bCertificateDataGridView.Size = New-Object System.Drawing.Size(580, 500)
$form.Controls.Add($p7bCertificateDataGridView)

# Replace Button
$replaceButton = New-Object System.Windows.Forms.Button
$replaceButton.Location = New-Object System.Drawing.Point(10, 560)
$replaceButton.Size = New-Object System.Drawing.Size(150, 30)
$replaceButton.Text = "Replace Selected"
$replaceButton.Enabled = $false
$form.Controls.Add($replaceButton)

# Chain Button
$chainButton = New-Object System.Windows.Forms.Button
$chainButton.Location = New-Object System.Drawing.Point(170, 560)
$chainButton.Size = New-Object System.Drawing.Size(150, 30)
$chainButton.Text = "Create Chain"
$chainButton.Enabled = $false
$form.Controls.Add($chainButton)

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

# Function to populate and highlight certificates in DataGridViews
function Populate-Certificates {
    # Clear existing data
    $keystoreCertificateDataGridView.DataSource = $null
    $p7bCertificateDataGridView.DataSource = $null

    if ($keystoreCollection) {
        # Create a DataTable for keystore certificates
        $keystoreTable = New-Object System.Data.DataTable
        $keystoreTable.Columns.Add("Subject", [string])
        $keystoreTable.Columns.Add("NotAfter", [datetime])
        $keystoreTable.Columns.Add("SKI", [string])

        foreach ($cert in $keystoreCollection) {
            $row = $keystoreTable.NewRow()
            $row.Subject = $cert.Subject
            $row.NotAfter = $cert.NotAfter
            $row.SKI = [System.BitConverter]::ToString($cert.SubjectKeyIdentifier).Replace("-", "")
            $keystoreTable.Rows.Add($row)
        }

        $keystoreCertificateDataGridView.DataSource = $keystoreTable

        # Color formatting for keystore certificates
        for ($i = 0; $i -lt $keystoreCertificateDataGridView.Rows.Count; $i++) {
            if ($keystoreCertificateDataGridView.Rows[$i].Cells["NotAfter"].Value -lt (Get-Date)) {
                $keystoreCertificateDataGridView.Rows[$i].DefaultCellStyle.ForeColor = 'Red'
            }
            if ($p7bCollection) {
                $matchingCert = $p7bCollection | Where-Object {
                    [System.BitConverter]::ToString($_.SubjectKeyIdentifier).Replace("-", "") -eq $keystoreCertificateDataGridView.Rows[$i].Cells["SKI"].Value
                }
                if ($matchingCert) {
                    $keystoreCertificateDataGridView.Rows[$i].DefaultCellStyle.BackColor = 'Green'
                }
            }
        }
    }

    if ($p7bCollection) {
        # Create a DataTable for P7B certificates
        $p7bTable = New-Object System.Data.DataTable
        $p7bTable.Columns.Add("Subject", [string])
        $p7bTable.Columns.Add("SKI", [string])

        foreach ($cert in $p7bCollection) {
            $row = $p7bTable.NewRow()
            $row.Subject = $cert.Subject
            $row.SKI = [System.BitConverter]::ToString($cert.SubjectKeyIdentifier).Replace("-", "")
            $p7bTable.Rows.Add($row)
        }

        $p7bCertificateDataGridView.DataSource = $p7bTable

        # Color formatting for P7B certificates (matching SKIs)
        for ($i = 0; $i -lt $p7bCertificateDataGridView.Rows.Count; $i++) {
            if ($keystoreCollection) {
                $matchingCert = $keystoreCollection | Where-Object {
                    [System.BitConverter]::ToString($_.SubjectKeyIdentifier).Replace("-", "") -eq $p7bCertificateDataGridView.Rows[$i].Cells["SKI"].Value
                }
                if ($matchingCert) {
                    $p7bCertificateDataGridView.Rows[$i].DefaultCellStyle.BackColor = 'Green'
                }
            }
        }
    }
}

# Function to create certificate chain
function Create-CertificateChain {
    $personalCert = $keystoreCollection | Where-Object {$_.HasPrivateKey -eq $true}
    if (-not $personalCert) {
        [System.Windows.Forms.MessageBox]::Show("No personal certificate found in the keystore.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid

    # Add the personal certificate to the chain
    $chain.Build($personalCert)

    # Add extra certificates from P7B to the chain
    foreach ($extraCert in $p7bCollection) {
        if ($chain.ChainElements.Count -gt 1) {
            break  # Stop if the chain already has an issuer
        }
        if ($extraCert.Subject -ne $personalCert.Subject) {
            $chain.ChainPolicy.ExtraStore.Add($extraCert)
        }
    }

    if ($chain.ChainElements.Count -gt 1) {
        # Save the chained certificate to a new PFX file
        $chainedCertPath = [System.IO.Path]::ChangeExtension($keystorePath, "chained.pfx")
        $chain.ChainElements[0].Certificate.Export($chainedCertPath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
        [System.Windows.Forms.MessageBox]::Show("Certificate chain created successfully! Saved to: $($chainedCertPath)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } else {
        [System.Windows.Forms.MessageBox]::Show("Could not create a complete certificate chain.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}

# Open Keystore Button Click Event
$openKeystoreButton.Add_Click({
    if ($openKeystoreFileDialog.ShowDialog() -eq "OK") {
        $keystorePath = $openKeystoreFileDialog.FileName
        $keystorePathLabel.Text = $keystorePath

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

                    # Call the function to populate and highlight certificates
                    Populate-Certificates
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
    $chainButton.Enabled = ($keystoreCollection -ne $null) -and ($p7bCollection -ne $null)
})

# Open P7B Button Click Event
$openP7BButton.Add_Click({
    if ($openP7BFileDialog.ShowDialog() -eq "OK") {
        $p7bPath = $openP7BFileDialog.FileName
        $p7bPathLabel.Text = $p7bPath

        try {
            $p7bCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $p7bCollection.Import($p7bPath)

            # Call the function to populate and highlight certificates
            Populate-Certificates
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
    $replaceButton.Enabled = ($keystoreCollection -ne $null) -and ($p7bCollection -ne $null)
    $chainButton.Enabled = ($keystoreCollection -ne $null) -and ($p7bCollection -ne $null)
})

# Replace Button Click Event
$replaceButton.Add_Click({
    $keystoreCertIndex = $keystoreCertificateDataGridView.SelectedRows[0]?.Index
    $p7bCertIndex = $p7bCertificateDataGridView.SelectedRows[0]?.Index

    if ($keystoreCertIndex -ne $null -and $p7bCertIndex -ne $null) {
        $keystoreCert = $keystoreCollection[$keystoreCertIndex]
        $p7bCert = $p7bCollection[$p7bCertIndex]

        $keystoreCollection.Remove($keystoreCert)
        $keystoreCollection.Add($p7bCert)

        # Update the keystore file (requires password)
        $keystoreCollection.Export($keystorePath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

        # Refresh the DataGridViews to reflect the change and highlight matches
        Populate-Certificates

        [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
})

# Chain Button Click Event
$chainButton.Add_Click({
    Create-CertificateChain
})

$form.Add_Shown({$form.Activate()})
$form.ShowDialog()
