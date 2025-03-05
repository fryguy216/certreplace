# Requires -Modules @{ ModuleName = 'PKI'; ModuleVersion = '1.0.0.0' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.InteropServices # Added for Marshal

function Get-KeystoreCertificates {
    param (
        [string]$KeystorePath,
        [System.Security.SecureString]$Password
    )

    try {
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $keystore.Import($KeystorePath, $passwordString, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
        return $keystore
    }
    catch {
        Write-Warning "Error opening keystore: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error opening keystore: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
    finally {
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if($Password){
            $Password.Dispose()
        }
    }
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
        # Reopen the keystore with read/write access
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $keystore.Import($KeystorePath, $passwordString, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

        # Find the index of the certificate to be replaced (more robust than relying on selected row index)
        $indexToReplace = -1
        for ($i = 0; $i -lt $keystore.Count; $i++) {
            if ($keystore[$i].Thumbprint -eq $OldCertificate.Thumbprint) {
                $indexToReplace = $i
                break
            }
        }

        if ($indexToReplace -eq -1) {
            Write-Warning "The certificate to be replaced was not found in the keystore."
             [System.Windows.Forms.MessageBox]::Show("The certificate to be replaced was not found in the keystore.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return $false
        }
        #Remove old certificate
        $keystore.RemoveAt($indexToReplace)

        # Add the new certificate
        $keystore.Add($NewCertificate)

        # Save the changes back to the keystore file
        $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
        [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)

        Write-Host "Certificate replaced successfully." -ForegroundColor Green
        [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return $true
    }
    catch {
        Write-Warning "Error replacing certificate: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error replacing certificate: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $false
    }
    finally {
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
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck #For the example, avoid checking
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag #For the example, avoid checking
        $chain.ChainPolicy.ExtraStore.AddRange($IntermediateCertificates)

        if ($chain.Build($LeafCertificate)) {
            $chainedCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $chainedCerts.Add($LeafCertificate)

            # Add intermediate and root certificates from the chain
            foreach ($element in $chain.ChainElements) {
                 if ($element.Certificate.Thumbprint -ne $LeafCertificate.Thumbprint)
                 {
                    $chainedCerts.Add($element.Certificate)
                 }
            }

             # Prompt for the output PFX file path
            $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $SaveFileDialog.Filter = "PFX files (*.pfx)|*.pfx"
            $SaveFileDialog.Title = "Save Chained Certificate As"
            $SaveFileDialog.FileName = "chained_certificate.pfx"
            if ($SaveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $outputPath = $SaveFileDialog.FileName

                 # Export the chained certificates to a new PFX file
                 $pfxBytes = $chainedCerts.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
                 [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
                Write-Host "Certificate chain saved to: $outputPath" -ForegroundColor Green
                [System.Windows.Forms.MessageBox]::Show("Certificate chain saved to: $outputPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        }
        else {
            Write-Warning "Failed to build a valid certificate chain."
            [System.Windows.Forms.MessageBox]::Show("Failed to build a valid certificate chain.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            Write-Host "Chain Status:" -ForegroundColor Yellow
            foreach($status in $chain.ChainStatus){
                Write-Host ("  " + $status.StatusInformation) -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Warning "Error building certificate chain: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error building certificate chain: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    finally{
        if ($chain -ne $null){
            $chain.Reset() #reset the chain status
        }
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
         if($KeystorePassword){
            $KeystorePassword.Dispose()
        }
    }
}


function Get-P7BCertificates {
    param (
        [string]$P7BPath
    )

    try {
        $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $p7b.Import($P7BPath) # P7B doesn't have password.
        return $p7b
    }
    catch {
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

            # Highlight expired certificates
            if ($cert.NotAfter -lt [DateTime]::Now -or $cert.NotBefore -gt [DateTime]::Now) {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
            }

            # Highlight matching SKIs
            $ski = $cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}  # Subject Key Identifier OID
            if ($ski -and $MatchingSKIs.Contains($ski.Format(0))) { #0 = no formatting. We just need the value as string.
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
            }

            $DataGridView.ClearSelection() # avoid auto-selecting after changing the color.
        }
    }
}

function Get-CertificateSKI {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $skiExtension = $Certificate.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}  # Subject Key Identifier OID
    if ($skiExtension) {
        return $skiExtension.Format(0)  # Raw SKI value
    }
    return $null
}





function Compare-Certificates {
  $keystoreCerts = $keystoreDataGridView.DataSource
  $p7bCerts = $p7bDataGridView.DataSource

  if ($keystoreCerts -and $p7bCerts) {
    $matchingSKIs = New-Object System.Collections.ArrayList

    foreach ($keystoreCert in $keystoreCerts) {
      $keystoreSKI = Get-CertificateSKI $keystoreCert
      if ($keystoreSKI) {
        foreach ($p7bCert in $p7bCerts) {
          $p7bSKI = Get-CertificateSKI $p7bCert
          if ($p7bSKI -and $keystoreSKI -eq $p7bSKI) {
            $matchingSKIs.Add($keystoreSKI) | Out-Null  # Add to the list, suppress output
            break  # No need to continue inner loop once a match is found
          }
        }
      }
    }

    Show-Certificate -DataGridView $keystoreDataGridView -MatchingSKIs $matchingSKIs
    Show-Certificate -DataGridView $p7bDataGridView -MatchingSKIs $matchingSKIs
  }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Keystore and P7B Certificate Comparator"
$form.Size = New-Object System.Drawing.Size(1200, 500) # Adjusted height
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


$keystorePasswordLabel = New-Object System.Windows.Forms.Label  # Keep the label for context
$keystorePasswordLabel.Location = New-Object System.Drawing.Point(10, 40)
$keystorePasswordLabel.Size = New-Object System.Drawing.Size(100, 20)
$keystorePasswordLabel.Text = "Password:"

$keystorePasswordField = New-Object System.Windows.Forms.TextBox #Keep for create chain
$keystorePasswordField.Location = New-Object System.Drawing.Point(110, 40)
$keystorePasswordField.Size = New-Object System.Drawing.Size(200, 20)
$keystorePasswordField.PasswordChar = "*"
$keystorePasswordField.Visible = $false # Hide it

$keystoreOpenButton = New-Object System.Windows.Forms.Button
$keystoreOpenButton.Location = New-Object System.Drawing.Point(320, 37)
$keystoreOpenButton.Size = New-Object System.Drawing.Size(75, 23)
$keystoreOpenButton.Text = "Open"

$keystoreDataGridView = New-Object System.Windows.Forms.DataGridView
$keystoreDataGridView.Location = New-Object System.Drawing.Point(10, 70)
$keystoreDataGridView.Size = New-Object System.Drawing.Size(580, 300)
$keystoreDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$keystoreDataGridView.AllowUserToAddRows = $false
$keystoreDataGridView.ReadOnly = $true;
$keystoreDataGridView.SelectionMode = "FullRowSelect"
$keystoreDataGridView.MultiSelect = $false; # Important: Only allow one selection

# --- P7B Controls ---

$p7bLabel = New-Object System.Windows.Forms.Label
$p7bLabel.Location = New-Object System.Drawing.Point(610, 10)
$p7bLabel.Size = New-Object System.Drawing.Size(100, 20)
$p7bLabel.Text = "P7B File:"

$p7bTextBox = New-Object System.Windows.Forms.TextBox
$p7bTextBox.Location = New-Object System.Drawing.Point(710, 10)
$p7bTextBox.Size = New-Object System.Drawing.Size(400, 20)
$p7bTextBox.ReadOnly = $true

$p7bBrowseButton = New-Object System.Windows.Forms.Button
$p7bBrowseButton.Location = New-Object System.Drawing.Point(1120, 7)
$p7bBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
$p7bBrowseButton.Text = "Browse..."

$p7bOpenButton = New-Object System.Windows.Forms.Button
$p7bOpenButton.Location = New-Object System.Drawing.Point(710, 37) #Adjust location if needed.
$p7bOpenButton.Size = New-Object System.Drawing.Size(75, 23)
$p7bOpenButton.Text = "Open"


$p7bDataGridView = New-Object System.Windows.Forms.DataGridView
$p7bDataGridView.Location = New-Object System.Drawing.Point(610, 70)
$p7bDataGridView.Size = New-Object System.Drawing.Size(580, 300)
$p7bDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$p7bDataGridView.AllowUserToAddRows = $false
$p7bDataGridView.ReadOnly = $true;
$p7bDataGridView.SelectionMode = "FullRowSelect"
$p7bDataGridView.MultiSelect = $false; # Important: Only allow one selection

# --- Action Buttons ---

$replaceButton = New-Object System.Windows.Forms.Button
$replaceButton.Location = New-Object System.Drawing.Point(10, 380)
$replaceButton.Size = New-Object System.Drawing.Size(150, 30)
$replaceButton.Text = "Replace Certificate"
$replaceButton.Enabled = $false  # Initially disabled

$createChainButton = New-Object System.Windows.Forms.Button
$createChainButton.Location = New-Object System.Drawing.Point(170, 380)
$createChainButton.Size = New-Object System.Drawing.Size(150, 30)
$createChainButton.Text = "Create Chain"
$createChainButton.Enabled = $false # Initially disabled

# --- Event Handlers ---

$keystoreOpenButton.Add_Click({
    if ([string]::IsNullOrEmpty($keystoreTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a keystore file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    # Get password securely
    $securePassword = Read-Host "Enter keystore password" -AsSecureString

    $keystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $securePassword

    if ($keystoreCerts) {
        $keystoreDataGridView.DataSource = $keystoreCerts
        $keystoreDataGridView.Columns["PrivateKey"].Visible = $false # Hide the private key

         # Check if a P7B file is already open and compare certificates
        if (![string]::IsNullOrEmpty($p7bTextBox.Text)) {
            $p7bCerts = Get-P7BCertificates -P7BPath $p7bTextBox.Text
            if ($p7bCerts) {
                $p7bDataGridView.DataSource = $p7bCerts
                Compare-Certificates
            }
        } else {
             #If no P7B opened, simply highlight expired.
              $matchingSkis = New-Object System.Collections.ArrayList #empty list
              Show-Certificate -DataGridView $keystoreDataGridView -MatchingSKIs $matchingSkis
        }
    }
     $replaceButton.Enabled = $false
     $createChainButton.Enabled = $false
     $securePassword.Dispose() # Dispose immediately after use
})

$p7bOpenButton.Add_Click({
    if ([string]::IsNullOrEmpty($p7bTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a P7B file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $p7bCerts = Get-P7BCertificates -P7BPath $p7bTextBox.Text

    if ($p7bCerts) {
        $p7bDataGridView.DataSource = $p7bCerts

        # Check if a keystore file is already open and compare
        if (![string]::IsNullOrEmpty($keystoreTextBox.Text)) {
              # Get password securely
              $securePassword = Read-Host "Enter keystore password" -AsSecureString
              $keystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $securePassword

              if($keystoreCerts)
              {
                $keystoreDataGridView.DataSource = $keystoreCerts
                $keystoreDataGridView.Columns["PrivateKey"].Visible = $false # Hide the private key
                Compare-Certificates
              }
              $securePassword.Dispose() # Dispose immediately after use
        }
         else {
            #If no Keystore is opened.
             $matchingSkis = New-Object System.Collections.ArrayList
             Show-Certificate -DataGridView $p7bDataGridView -MatchingSKIs $matchingSkis
         }
    }
    $replaceButton.Enabled = $false
    $createChainButton.Enabled = $false
})


$keystoreBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "Keystore files (*.p12;*.pfx)|*.p12;*.pfx"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $keystoreTextBox.Text = $OpenFileDialog.FileName
    }
})

$p7bBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $p7bTextBox.Text = $OpenFileDialog.FileName
    }
})

$replaceButton.Add_Click({
    # Get selected certificates
    $selectedKeystoreCert = $keystoreDataGridView.SelectedRows[0].DataBoundItem
    $selectedP7BCert = $p7bDataGridView.SelectedRows[0].DataBoundItem

    if ($selectedKeystoreCert -and $selectedP7BCert) {
        # Get password securely
        $securePassword = Read-Host "Enter keystore password to replace certificate" -AsSecureString

        $replaceResult = Set-KeystoreCertificate -KeystorePath $keystoreTextBox.Text -KeystorePassword $securePassword -OldCertificate $selectedKeystoreCert -NewCertificate $selectedP7BCert
        $securePassword.Dispose()

        if($replaceResult){
            # Refresh the keystore DataGridView
            # Get password securely
            $refreshSecurePassword = Read-Host "Enter keystore password to refresh view" -AsSecureString
            $updatedKeystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $refreshSecurePassword
            $refreshSecurePassword.Dispose() #Dispose
            if ($updatedKeystoreCerts) {
                $keystoreDataGridView.DataSource = $updatedKeystoreCerts
                $keystoreDataGridView.Columns["PrivateKey"].Visible = $false
                Compare-Certificates # Re-compare after replacement
            }
        }
    }
    else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and one from P7B to replace.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }

     $replaceButton.Enabled = $false
     $createChainButton.Enabled = $false
})

$createChainButton.Add_Click({
      # Get selected certificates
    $selectedKeystoreCert = $keystoreDataGridView.SelectedRows[0].DataBoundItem
    $p7bCerts = $p7bDataGridView.DataSource

    if($selectedKeystoreCert -and $p7bCerts)
    {
        # Get password securely
        $securePassword = Read-Host "Enter keystore password to create chain" -AsSecureString
        Build-CertificateChain -LeafCertificate $selectedKeystoreCert -IntermediateCertificates $p7bCerts -KeystorePassword $securePassword
        $securePassword.Dispose() #Dispose
    }
     else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and ensure the P7B is loaded.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }

    $replaceButton.Enabled = $false
    $createChainButton.Enabled = $false

})

# --- Enable buttons if appropriate ---
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
$form.Controls.Add($keystorePasswordLabel)
$form.Controls.Add($keystorePasswordField)
$form.Controls.Add($keystoreOpenButton)
$form.Controls.Add($keystoreDataGridView)
$form.Controls.Add($p7bLabel)
$form.Controls.Add($p7bTextBox)
$form.Controls.Add($p7bBrowseButton)
$form.Controls.Add($p7bOpenButton)
$form.Controls.Add($p7bDataGridView)
$form.Controls.Add($replaceButton)
$form.Controls.Add($createChainButton)

# --- Show the Form ---
$form.ShowDialog()
