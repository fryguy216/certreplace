# Requires -Modules @{ ModuleName = 'PKI'; ModuleVersion = '1.0.0.0' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.InteropServices

# --- Functions ---

function Get-KeystorePassword {
    # Create a form for password entry.
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Enter Keystore Password"
        Size          = New-Object System.Drawing.Size(300, 150)  # Form size
        StartPosition = "CenterScreen"
    }

    # Add a label for the password field.
    $label = New-Object System.Windows.Forms.Label -Property @{
        Location = New-Object System.Drawing.Point(10, 20)
        Size     = New-Object System.Drawing.Size(280, 20)
        Text     = "Password:"
    }
    $form.Controls.Add($label)

    # Add a textbox for password input (masked).
    $textBox = New-Object System.Windows.Forms.TextBox -Property @{
        Location   = New-Object System.Drawing.Point(10, 40)
        Size       = New-Object System.Drawing.Size(260, 20)
        PasswordChar = "*"  # Mask the password input
    }
    $form.Controls.Add($textBox)

    # Add an "OK" button.
    $okButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(130, 80)
        Size     = New-Object System.Drawing.Size(75, 23)
        Text     = "OK"
        DialogResult = [System.Windows.Forms.DialogResult]::OK
    }
    $form.Controls.Add($okButton)
    $form.AcceptButton = $okButton  # "OK" is the default button

    # Add a "Cancel" button.
    $cancelButton = New-Object System.Windows.Forms.Button -Property @{
        Location     = New-Object System.Drawing.Point(210, 80)
        Size         = New-Object System.Drawing.Size(75, 23)
        Text         = "Cancel"
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    }
    $form.Controls.Add($cancelButton)
    $form.CancelButton = $cancelButton # Cancel button closes

    # Show the form and get the result.
    $result = $form.ShowDialog()

    # If the user clicked "OK", create a SecureString from the input.
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $securePassword = New-Object System.Security.SecureString
        foreach ($char in $textBox.Text.ToCharArray()) {
            $securePassword.AppendChar($char)
        }
        return $securePassword
    }
    else {
        return $null  # Return null if cancelled
    }
    $form.Dispose()
}

function Get-KeystoreCertificates {
    param (
        [string]$KeystorePath,
        [System.Security.SecureString]$Password
    )

    try {
        # Create a new X509Certificate2Collection object.
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        # Convert the SecureString password to a BSTR.
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        # Import the keystore, specifying exportable and persistent keys.
        $keystore.Import($KeystorePath, $passwordString, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
        return $keystore  # Return the collection of certificates.
    }
    catch {
        # Handle any errors during import.
        Write-Warning "Error opening keystore: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error opening keystore: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
    finally {
        # Always free the BSTR and dispose SecureString, even if there's an error.
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if($Password){
            $Password.Dispose()
        }
    }
}

function Get-P7BCertificates {
    param (
        [string]$P7BPath
    )

    try {
        # Create a new X509Certificate2Collection.
        $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $p7b.Import($P7BPath)  # P7B files don't require a password.
        return $p7b  # Return the collection of certificates.
    }
    catch {
        # Handle any errors during import.
        Write-Warning "Error opening P7B file: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

function Show-Certificate {
    param (
        [System.Windows.Forms.DataGridView]$DataGridView,
        [System.Collections.ArrayList]$MatchingSKIs
    )

    foreach ($row in $DataGridView.Rows) {
        if ($row.DataBoundItem -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $cert = $row.DataBoundItem

            # Highlight expired certificates in red.
            if ($cert.NotAfter -lt [DateTime]::Now -or $cert.NotBefore -gt [DateTime]::Now) {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
            }

            # Highlight matching certificates (by SKI) in light green.
            $ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
            if ($ski -and $MatchingSKIs.Contains($ski.Format(0))) {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
            }
        }
    }
    # No ClearSelection here
}

function Get-CertificateSKI {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    # Get the Subject Key Identifier (SKI) extension.
    $skiExtension = $Certificate.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
    if ($skiExtension) {
        return $skiExtension.Format(0)  # Return the formatted SKI.
    }
    return $null  # Return null if no SKI is found.
}

function Set-KeystoreCertificate {
    param(
        [string]$KeystorePath,
        [System.Security.SecureString]$KeystorePassword,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$OldCertificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$NewCertificate
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
    $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    try {
        # Load the keystore.
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $keystore.Import($KeystorePath, $passwordString, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

        # Find the index of the certificate to replace.
        $indexToReplace = -1
        for ($i = 0; $i -lt $keystore.Count; $i++) {
            if ($keystore[$i].Thumbprint -eq $OldCertificate.Thumbprint) {
                $indexToReplace = $i
                break
            }
        }

        # If the certificate isn't found, show an error and return.
        if ($indexToReplace -eq -1) {
            Write-Warning "The certificate to be replaced was not found in the keystore."
             [System.Windows.Forms.MessageBox]::Show("The certificate to be replaced was not found in the keystore.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return $false
        }

        # Remove the old certificate and add the new one.
        $keystore.RemoveAt($indexToReplace)
        $keystore.Add($NewCertificate)

        # Export the updated keystore to a byte array.
        $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
        # Write the byte array back to the keystore file.
        [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)

        Write-Host "Certificate replaced successfully." -ForegroundColor Green
        [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return $true
    }
    catch {
        # Handle any errors during the replacement.
        Write-Warning "Error replacing certificate: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error replacing certificate: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $false
    }
    finally {
         # Always free the BSTR and dispose SecureString, even if there's an error.
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if($KeystorePassword){
            $KeystorePassword.Dispose()
        }
    }
}

function Build-CertificateChain {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$LeafCertificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$IntermediateCertificates,
        [System.Security.SecureString]$KeystorePassword
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
    $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    try {
        # Create a new X509Chain object.
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        # Configure the chain policy (no revocation check, no flags).
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        # Add the intermediate certificates to the chain's extra store.
        $chain.ChainPolicy.ExtraStore.AddRange($IntermediateCertificates)

        # Try to build the chain.
        if ($chain.Build($LeafCertificate)) {
            # If the chain builds successfully, create a new collection.
            $chainedCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
             #Add the leaf/end certificate
            $chainedCerts.Add($LeafCertificate)
            # Add the chain elements (excluding the leaf certificate itself).
            foreach ($element in $chain.ChainElements) {
                 if ($element.Certificate.Thumbprint -ne $LeafCertificate.Thumbprint)
                 {
                    $chainedCerts.Add($element.Certificate)
                 }
            }

            # Create a SaveFileDialog to let the user choose where to save the chain.
            $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $SaveFileDialog.Filter = "PFX files (*.pfx)|*.pfx"
            $SaveFileDialog.Title = "Save Chained Certificate As"
            $SaveFileDialog.FileName = "chained_certificate.pfx"  # Default filename
            if ($SaveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                # If the user clicks "OK", get the selected file path.
                $outputPath = $SaveFileDialog.FileName
                # Export the chained certificates as a PFX file.
                 $pfxBytes = $chainedCerts.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
                 # Write the PFX data to the file.
                 [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
                Write-Host "Certificate chain saved to: $outputPath" -ForegroundColor Green
                [System.Windows.Forms.MessageBox]::Show("Certificate chain saved to: $outputPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        }
        else {
            # If the chain build fails, show an error.
            Write-Warning "Failed to build a valid certificate chain."
            [System.Windows.Forms.MessageBox]::Show("Failed to build a valid certificate chain.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            Write-Host "Chain Status:" -ForegroundColor Yellow
            foreach($status in $chain.ChainStatus){
                Write-Host ("  " + $status.StatusInformation) -ForegroundColor Yellow
            }
        }
    }
    catch {
        # Handle any errors during chain building.
        Write-Warning "Error building certificate chain: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error building certificate chain: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    finally{
        # Always reset the chain and free the BSTR and SecureString.
        if ($chain -ne $null){
            $chain.Reset()
        }
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
         if($KeystorePassword){
            $KeystorePassword.Dispose()
        }
    }
}
function Compare-Certificates {
  param (
        [System.Windows.Forms.DataGridView]$KeystoreDataGridView,
        [System.Windows.Forms.DataGridView]$P7bDataGridView
    )
  $keystoreCerts = $KeystoreDataGridView.DataSource
  $p7bCerts = $P7bDataGridView.DataSource

  if ($keystoreCerts -and $p7bCerts) {
    $matchingSKIs = New-Object System.Collections.ArrayList

    foreach ($keystoreCert in $keystoreCerts) {
      $keystoreSKI = Get-CertificateSKI $keystoreCert
      if ($keystoreSKI) {
        foreach ($p7bCert in $p7bCerts) {
          $p7bSKI = Get-CertificateSKI $p7bCert
          if ($p7bSKI -and $keystoreSKI -eq $p7bSKI) {
            $matchingSKIs.Add($keystoreSKI) | Out-Null
            break
          }
        }
      }
    }

    Show-Certificate -DataGridView $KeystoreDataGridView -MatchingSKIs $matchingSKIs
    Show-Certificate -DataGridView $P7bDataGridView -MatchingSKIs $matchingSKIs
  }
   else {
        # Clear any previous highlighting if one of the DataGridViews is empty
        Show-Certificate -DataGridView $KeystoreDataGridView -MatchingSKIs @()
        Show-Certificate -DataGridView $P7bDataGridView -MatchingSKIs @()
    }
}


# --- GUI Setup ---

$form = New-Object System.Windows.Forms.Form
$form.Text = "Keystore and P7B Certificate Comparator"
$form.Size = New-Object System.Drawing.Size(1250, 600)
$form.StartPosition = "CenterScreen"

# --- Keystore Controls ---

$keystoreLabel = New-Object System.Windows.Forms.Label
$keystoreLabel.Location = New-Object System.Drawing.Point(10, 10)
$keystoreLabel.Size = New-Object System.Drawing.Size(100, 20)
$keystoreLabel.Text = "Keystore File:"

$keystoreTextBox = New-Object System.Windows.Forms.TextBox
$keystoreTextBox.Location = New-Object System.Drawing.Point(110, 10)
$keystoreTextBox.Size = New-Object System.Drawing.Size(400, 20)
$keystoreTextBox.ReadOnly = $true

$keystoreBrowseButton = New-Object System.Windows.Forms.Button
$keystoreBrowseButton.Location = New-Object System.Drawing.Point(520, 7)
$keystoreBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
$keystoreBrowseButton.Text = "Browse..."

$keystoreOpenButton = New-Object System.Windows.Forms.Button
$keystoreOpenButton.Location = New-Object System.Drawing.Point(110, 40)  # Adjusted location
$keystoreOpenButton.Size = New-Object System.Drawing.Size(75, 23)
$keystoreOpenButton.Text = "Open"

$keystoreDataGridView = New-Object System.Windows.Forms.DataGridView
$keystoreDataGridView.Location = New-Object System.Drawing.Point(10, 70)
$keystoreDataGridView.Size = New-Object System.Drawing.Size(600, 300) #Increased the width
$keystoreDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$keystoreDataGridView.AllowUserToAddRows = $false
$keystoreDataGridView.ReadOnly = $true;
$keystoreDataGridView.SelectionMode = "FullRowSelect"
$keystoreDataGridView.MultiSelect = $false;

# --- P7B Controls ---

$p7bLabel = New-Object System.Windows.Forms.Label
$p7bLabel.Location = New-Object System.Drawing.Point(620, 10) # Adjusted X coordinate
$p7bLabel.Size = New-Object System.Drawing.Size(100, 20)
$p7bLabel.Text = "P7B File:"

$p7bTextBox = New-Object System.Windows.Forms.TextBox
$p7bTextBox.Location = New-Object System.Drawing.Point(720, 10) # Adjusted X coordinate
$p7bTextBox.Size = New-Object System.Drawing.Size(400, 20)
$p7bTextBox.ReadOnly = $true

$p7bBrowseButton = New-Object System.Windows.Forms.Button
$p7bBrowseButton.Location = New-Object System.Drawing.Point(1130, 7) # Adjusted X coordinate
$p7bBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
$p7bBrowseButton.Text = "Browse..."


$p7bDataGridView = New-Object System.Windows.Forms.DataGridView
$p7bDataGridView.Location = New-Object System.Drawing.Point(620, 70) # Adjusted X coordinate
$p7bDataGridView.Size = New-Object System.Drawing.Size(600, 300) #Increased the width
$p7bDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$p7bDataGridView.AllowUserToAddRows = $false
$p7bDataGridView.ReadOnly = $true;
$p7bDataGridView.SelectionMode = "FullRowSelect"
$p7bDataGridView.MultiSelect = $false;

# --- Action Buttons ---
$compareButton = New-Object System.Windows.Forms.Button
$compareButton.Location = New-Object System.Drawing.Point(10, 380)
$compareButton.Size = New-Object System.Drawing.Size(150, 30)
$compareButton.Text = "Compare Certificates"
$compareButton.Enabled = $false

$replaceButton = New-Object System.Windows.Forms.Button
$replaceButton.Location = New-Object System.Drawing.Point(170, 380)
$replaceButton.Size = New-Object System.Drawing.Size(150, 30)
$replaceButton.Text = "Replace Certificate"
$replaceButton.Enabled = $false

$createChainButton = New-Object System.Windows.Forms.Button
$createChainButton.Location = New-Object System.Drawing.Point(330, 380)
$createChainButton.Size = New-Object System.Drawing.Size(150, 30)
$createChainButton.Text = "Create Chain"
$createChainButton.Enabled = $false

# --- DataBindingComplete event for keystoreDataGridView ---
$keystoreDataGridView.add_DataBindingComplete({
    if ($keystoreDataGridView.Columns.Contains("PrivateKey")) {
        $keystoreDataGridView.Columns["PrivateKey"].Visible = $false
    }
})

# --- Event Handlers ---

$keystoreOpenButton.Add_Click({
    if ([string]::IsNullOrEmpty($keystoreTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a keystore file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $securePassword = Get-KeystorePassword

    if ($securePassword) {
        $keystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $securePassword

        if ($keystoreCerts) {
            $keystoreDataGridView.DataSource = $keystoreCerts
        }
        $securePassword.Dispose()
    }
     # Disable buttons until Compare is clicked
    $replaceButton.Enabled = $false
    $createChainButton.Enabled = $false
    $compareButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)

})


$p7bBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $p7bTextBox.Text = $OpenFileDialog.FileName
        $p7bCerts = Get-P7BCertificates -P7BPath $p7bTextBox.Text
        if ($p7bCerts) {
            $p7bDataGridView.DataSource = $p7bCerts
        }
    }
     # Disable buttons until Compare is clicked
    $replaceButton.Enabled = $false
    $createChainButton.Enabled = $false
    $compareButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
})


$keystoreBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "Keystore files (*.p12;*.pfx)|*.p12;*.pfx"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $keystoreTextBox.Text = $OpenFileDialog.FileName
    }
})

$compareButton.Add_Click({
    Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
})


$replaceButton.Add_Click({
    $selectedKeystoreCert = $keystoreDataGridView.SelectedRows[0].DataBoundItem
    $selectedP7BCert = $p7bDataGridView.SelectedRows[0].DataBoundItem

    if ($selectedKeystoreCert -and $selectedP7BCert) {
        $securePassword = Get-KeystorePassword

        if ($securePassword) {
            $replaceResult = Set-KeystoreCertificate -KeystorePath $keystoreTextBox.Text -KeystorePassword $securePassword -OldCertificate $selectedKeystoreCert -NewCertificate $selectedP7BCert
             $securePassword.Dispose()
            if($replaceResult){
                $refreshSecurePassword = Get-KeystorePassword
                if($refreshSecurePassword)
                {
                    $updatedKeystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $refreshSecurePassword
                    $refreshSecurePassword.Dispose()
                    if ($updatedKeystoreCerts) {
                        $keystoreDataGridView.DataSource = $updatedKeystoreCerts
                        Compare-Certificates  -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView # Re-compare after replacing
                    }
                }

            }
        }
    }
    else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and one from P7B to replace.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }

     $replaceButton.Enabled = $false
     $createChainButton.Enabled = $false
     $compareButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
})

$createChainButton.Add_Click({
    $selectedKeystoreCert = $keystoreDataGridView.SelectedRows[0].DataBoundItem
    $p7bCerts = $p7bDataGridView.DataSource

    if($selectedKeystoreCert -and $p7bCerts)
    {
        $securePassword = Get-KeystorePassword
        if($securePassword)
        {
            Build-CertificateChain -LeafCertificate $selectedKeystoreCert -IntermediateCertificates $p7bCerts -KeystorePassword $securePassword
             $securePassword.Dispose()
        }
    }
     else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and ensure the P7B is loaded.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }

    $replaceButton.Enabled = $false
    $createChainButton.Enabled = $false
    $compareButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)

})

$keystoreDataGridView.add_SelectionChanged({
    if($keystoreDataGridView.SelectedRows.Count -gt 0 -and $p7bDataGridView.SelectedRows.Count -gt 0){
        $replaceButton.Enabled = $true
    }
    else{
        $replaceButton.Enabled = $false
    }

    if($keystoreDataGridView.SelectedRows.Count -gt 0 -and $p7bDataGridView.Rows.Count -gt 0)
    {
        $createChainButton.Enabled = $true;
    }
    else{
        $createChainButton.Enabled = $false
    }
})

$p7bDataGridView.add_SelectionChanged({
   if($keystoreDataGridView.SelectedRows.Count -gt 0 -and $p7bDataGridView.SelectedRows.Count -gt 0){
        $replaceButton.Enabled = $true
    }
    else{
        $replaceButton.Enabled = $false
    }

    if($keystoreDataGridView.SelectedRows.Count -gt 0 -and $p7bDataGridView.Rows.Count -gt 0)
    {
        $createChainButton.Enabled = $true;
    }
     else{
        $createChainButton.Enabled = $false
    }
})

# --- Add Controls to Form ---

$form.Controls.Add($keystoreLabel)
$form.Controls.Add($keystoreTextBox)
$form.Controls.Add($keystoreBrowseButton)
$form.Controls.Add($keystoreOpenButton)
$form.Controls.Add($keystoreDataGridView)
$form.Controls.Add($p7bLabel)
$form.Controls.Add($p7bTextBox)
$form.Controls.Add($p7bBrowseButton)
$form.Controls.Add($p7bDataGridView)
$form.Controls.Add($replaceButton)
$form.Controls.Add($createChainButton)
$form.Controls.Add($compareButton)

# --- Show the Form ---
$form.ShowDialog()
