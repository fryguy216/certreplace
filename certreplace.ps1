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

# Function to highlight matching certificates and expired certificates
function Highlight-Certificates {
    # Only clear the keystore listbox if a keystore file is loaded
    if ($keystoreCollection) {
        $keystoreCertificateListBox.Items.Clear()
    }
    # Only clear the P7B listbox if a P7B file is loaded
    if ($p7bCollection) {
        $p7bCertificateListBox.Items.Clear()
    }

    if ($keystoreCollection) {
        foreach ($keystoreCert in $keystoreCollection) {
            $matchingCert = $null
            if ($p7bCollection) {
                $matchingCert = $p7bCollection | Where-Object {$_.SubjectKeyIdentifier -eq $keystoreCert.SubjectKeyIdentifier}
            }
            if ($matchingCert) {
                # Highlight matching SKI with green background
                $keystoreItem = New-Object System.Windows.Forms.ListViewItem($keystoreCert.Subject)
                $keystoreItem.BackColor = 'Green'
                $keystoreCertificateListBox.Items.Add($keystoreItem)

                $p7bItem = New-Object System.Windows.Forms.ListViewItem($matchingCert.Subject)
                $p7bItem.BackColor = 'Green'
                $p7bCertificateListBox.Items.Add($p7bItem)
            } else {
                $keystoreItem = New-Object System.Windows.Forms.ListViewItem($keystoreCert.Subject)
                # Highlight expired certificates with red text
                if ($keystoreCert.NotAfter -lt (Get-Date)) {
                    $keystoreItem.ForeColor = 'Red'
                }
                $keystoreCertificateListBox.Items.Add($keystoreItem)
            }
        }
    }

    if ($p7bCollection) {
        foreach ($p7bCert in $p7bCollection) {
            $matchingCert = $null
            if ($keystoreCollection) {
                $matchingCert = $keystoreCollection | Where-Object {$_.SubjectKeyIdentifier -eq $p7bCert.SubjectKeyIdentifier}
            }
            if (-not $matchingCert) {
                $p7bCertificateListBox.Items.Add($p7bCert.Subject)
            }
        }
    }
}

# Function to create certificate chain (unchanged)
# ... (rest of the code remains the same)
