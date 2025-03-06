# Requires -Modules @{ ModuleName = 'PKI'; ModuleVersion = '1.0.0.0' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.InteropServices

# --- Global Variables ---
$keystoreCertificates = New-Object System.Collections.ArrayList
$p7bCertificates = New-Object System.Collections.ArrayList
$infoMessages = New-Object System.Collections.ArrayList #For info messages.

function Get-KeystorePassword {
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Enter Keystore Password"
        Size          = New-Object System.Drawing.Size(300, 150)
        StartPosition = "CenterScreen"
    }

    $label = New-Object System.Windows.Forms.Label -Property @{
        Location = New-Object System.Drawing.Point(10, 20)
        Size     = New-Object System.Drawing.Size(280, 20)
        Text     = "Password:"
    }
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox -Property @{
        Location   = New-Object System.Drawing.Point(10, 40)
        Size       = New-Object System.Drawing.Size(260, 20)
        PasswordChar = "*"
    }
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(130, 80)
        Size     = New-Object System.Drawing.Size(75, 23)
        Text     = "OK"
        DialogResult = [System.Windows.Forms.DialogResult]::OK
    }
    $form.Controls.Add($okButton)
    $form.AcceptButton = $okButton

    $cancelButton = New-Object System.Windows.Forms.Button -Property @{
        Location     = New-Object System.Drawing.Point(210, 80)
        Size         = New-Object System.Drawing.Size(75, 23)
        Text         = "Cancel"
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    }
    $form.Controls.Add($cancelButton)
    $form.CancelButton = $cancelButton

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $securePassword = New-Object System.Security.SecureString
        foreach ($char in $textBox.Text.ToCharArray()) {
            $securePassword.AppendChar($char)
        }
        return $securePassword
    }
    else {
        return $null
    }
    $form.Dispose()
}

function Get-KeystoreCertificates {
    param (
        [string]$KeystorePath,
        [System.Security.SecureString]$Password
    )

    try {
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        $keystore.Import($KeystorePath, $passwordString, $flags)
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

function Get-P7BCertificates {
    param (
        [string]$P7BPath
    )

    try {
        $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $p7b.Import($P7BPath)
        return $p7b
    }
    catch {
        Write-Warning "Error opening P7B file: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

function Get-CertificateSKI {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $skiExtension = $Certificate.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
    if ($skiExtension) {
        return $skiExtension.Format(0)
    }
    return $null
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
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        $keystore.Import($KeystorePath, $passwordString, $flags)


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
        $keystore.RemoveAt($indexToReplace)
        $keystore.Add($NewCertificate)

        $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
        [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)

        Write-Host "Certificate replaced successfully." -ForegroundColor Green
        [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return $true
    }
    catch {
        $errorMessage = "Error replacing certificate: $($_.Exception.Message)"
        Write-Warning $errorMessage
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.ExtraStore.AddRange($IntermediateCertificates)

        if ($chain.Build($LeafCertificate)) {
            $chainedCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $chainedCerts.Add($LeafCertificate)

            foreach ($element in $chain.ChainElements) {
                 if ($element.Certificate.Thumbprint -ne $LeafCertificate.Thumbprint)
                 {
                    $chainedCerts.Add($element.Certificate)
                 }
            }

            $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $SaveFileDialog.Filter = "PFX files (*.pfx)|*.pfx"
            $SaveFileDialog.Title = "Save Chained Certificate As"
            $SaveFileDialog.FileName = "chained_certificate.pfx"
            if ($SaveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $outputPath = $SaveFileDialog.FileName
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

  # Clear previous messages
  $infoMessages.Clear()

  $keystoreData = $KeystoreDataGridView.DataSource
  $p7bData = $P7bDataGridView.DataSource

    if ($keystoreData -is [System.Data.DataTable] -and $p7bData -is [System.Data.DataTable]) {
        # --- Check for duplicate SKIs in keystore ---
        $skiCounts = @{}
        foreach ($row in $keystoreData.Rows) {
            $ski = $row["SKI"]
            if ($ski) {
                if (!$skiCounts.ContainsKey($ski)) {
                    $skiCounts[$ski] = 0
                }
                $skiCounts[$ski]++
            }
        }
        foreach($ski in $skiCounts.Keys){
            if($skiCounts[$ski] -gt 1){
                 $infoMessages.Add("Keystore contains duplicate certificates, dedupe recommended") | Out-Null
                 break; #only add once.
            }
        }

        # --- Check for expired certificates in keystore ---
        foreach ($row in $keystoreData.Rows) {
          if ($row["NotAfter"] -lt [DateTime]::Now -or $row["NotBefore"] -gt [DateTime]::Now) {
            $infoMessages.Add("Keystore contains expired certificates, replacement recommended") | Out-Null
            break;  # Only need one message
          }
        }

        # --- Check for newer certificates in P7B ---
        foreach ($keystoreRow in $keystoreData.Rows) {
            $keystoreSKI = $keystoreRow["SKI"]
            $keystoreNotAfter = $keystoreRow["NotAfter"]
            if ($keystoreSKI -and $keystoreNotAfter) {
                foreach ($p7bRow in $p7bData.Rows) {
                    $p7bSKI = $p7bRow["SKI"]
                    $p7bNotAfter = $p7bRow["NotAfter"]
                    if ($p7bSKI -and $keystoreSKI -eq $p7bSKI -and $p7bNotAfter -gt $keystoreNotAfter) {
                        $infoMessages.Add("P7B contains newer certificates than those in the keystore, replacement recommended") | Out-Null
                         break 2  # exit both loops after first
                    }
                }
            }
        }

         # --- Check if P7B has valid chain for personal certs ---
        if($p7bData){
            foreach ($keystoreRow in $keystoreData.Rows)
            {
                $keystoreSKI = $keystoreRow["SKI"]
                # Find the personal certificate
                if ($keystoreSKI) {
                   $personalCert = $keystoreCertificates.Where({(Get-CertificateSKI $_) -eq $keystoreSKI}, 'First')
                   if($personalCert){
                        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain$infoMessages.Add("P7B contains newer certificates than a personal certificate in the keystore, chain rebuild recommended.") | Out-Null;
                                break; #exit on first match
                             }
                        }
                        $chain.Reset()
                   }
                }
            }
        }
    }

    # Update the information textbox
    $infoTextBox.Text = [string]::Join([Environment]::NewLine, $infoMessages)
}


function Cleanup-Keystore {
    param(
        [string]$KeystorePath,
        [System.Security.SecureString]$KeystorePassword,
        [System.Collections.ArrayList]$KeystoreCertificates,
        [System.Collections.ArrayList]$P7BCertificates
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
    $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    try {
        $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        $keystore.Import($KeystorePath, $passwordString, $flags)

        # --- 1. Remove Duplicate SKIs (Keep Latest Expiry) ---

        $skiGroups = @{}
        foreach ($cert in $KeystoreCertificates) {
            $ski = Get-CertificateSKI $cert
            if ($ski) {
                if (!$skiGroups.ContainsKey($ski)) {
                    $skiGroups[$ski] = New-Object System.Collections.ArrayList
                }
                $skiGroups[$ski].Add($cert)
            }
        }

        $certsToRemove = New-Object System.Collections.ArrayList
        foreach ($ski in $skiGroups.Keys) {
            $group = $skiGroups[$ski]
            if ($group.Count -gt 1) {
                # Sort by NotAfter (descending - latest first)
                $sortedGroup = $group | Sort-Object -Property NotAfter -Descending
                # Keep the first (latest), mark the rest for removal
                for ($i = 1; $i -lt $sortedGroup.Count; $i++) {
                    $certsToRemove.Add($sortedGroup[$i]) | Out-Null
                }
            }
        }

        foreach ($certToRemove in $certsToRemove) {
             Write-Host "Removing duplicate certificate (by SKI): $($certToRemove.Subject)" -ForegroundColor Yellow
            $keystore.Remove($certToRemove)
            $KeystoreCertificates.Remove($certToRemove) | Out-Null
        }


        # --- 2. Remove and Replace with P7B Matches ---
        $certsToRemove = New-Object System.Collections.ArrayList
        foreach ($keystoreCert in $KeystoreCertificates) {
            $keystoreSKI = Get-CertificateSKI $keystoreCert
            foreach($p7bCert in $P7BCertificates){
                $p7bSKI = Get-CertificateSKI $p7bCert
                if($keystoreSKI -eq $p7bSKI){
                    $certsToRemove.Add($keystoreCert) | Out-Null
                    Write-Host "Replacing certificate with P7B match (by SKI): $($keystoreCert.Subject)" -ForegroundColor Yellow
                    $keystore.Remove($keystoreCert)
                    $keystore.Add($p7bCert)
                    #Update the ArrayList
                    $KeystoreCertificates.Remove($keystoreCert) | Out-Null
                    $found = $false;
                    foreach($existingp7b in $P7bCertificates){
                        if($existingp7b.Thumbprint -eq $p7bCert.Thumbprint){
                            $found = $true;
                            break;
                        }
                    }
                    if(-not $found){
                        $P7bCertificates.Add($p7bCert) | Out-Null
                    }

                    break
                }
            }
        }

        # --- 3. Chain Management ---

       foreach($personalCert in $KeystoreCertificates){
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
            $intermediateCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
             foreach($cert in $P7bCertificates)
            {
                $intermediateCerts.Add($cert)
            }
            $chain.ChainPolicy.ExtraStore.AddRange($intermediateCerts)

            if($chain.Build($personalCert)){
                #Chain is Valid, proceed
                if($chain.ChainElements.Count -gt 1){
                    #It's a real chain, remove from keystore.
                     Write-Host "Rebuilding Chain For: $($personalCert.Subject)" -ForegroundColor Yellow
                    for($i = 1; $i -lt $chain.ChainElements.Count; $i++){ # The last element is the root, don't remove it.
                        $certToRemove = $chain.ChainElements[$i].Certificate
                        $keystore.Remove($certToRemove)
                        $KeystoreCertificates.Remove($certToRemove) | Out-Null
                    }
                }

            }
            $chain.Reset()
       }


        # --- Save Modified Keystore ---
        $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
        [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)

        Write-Host "Keystore cleanup complete." -ForegroundColor Green
        [System.Windows.Forms.MessageBox]::Show("Keystore cleanup complete.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
         return $true
    }
    catch {
        $errorMessage = "Error during keystore cleanup: $($_.Exception.Message)"
        Write-Warning $errorMessage
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $false
    }
    finally {
        if ($bstr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if ($KeystorePassword) {
            $KeystorePassword.Dispose()
        }
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
$keystoreOpenButton.Location = New-Object System.Drawing.Point(110, 40)
$keystoreOpenButton.Size = New-Object System.Drawing.Size(75, 23)
$keystoreOpenButton.Text = "Open"

$keystoreDataGridView = New-Object System.Windows.Forms.DataGridView
$keystoreDataGridView.Location = New-Object System.Drawing.Point(10, 70)
$keystoreDataGridView.Size = New-Object System.Drawing.Size(600, 300)
$keystoreDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$keystoreDataGridView.AllowUserToAddRows = $false
$keystoreDataGridView.ReadOnly = $true;
$keystoreDataGridView.SelectionMode = "FullRowSelect"
$keystoreDataGridView.MultiSelect = $false;

# --- P7B Controls ---

$p7bLabel = New-Object System.Windows.Forms.Label
$p7bLabel.Location = New-Object System.Drawing.Point(620, 10)
$p7bLabel.Size = New-Object System.Drawing.Size(100, 20)
$p7bLabel.Text = "P7B File:"

$p7bTextBox = New-Object System.Windows.Forms.TextBox
$p7bTextBox.Location = New-Object System.Drawing.Point(720, 10)
$p7bTextBox.Size = New-Object System.Drawing.Size(400, 20)
$p7bTextBox.ReadOnly = $true

$p7bBrowseButton = New-Object System.Windows.Forms.Button
$p7bBrowseButton.Location = New-Object System.Drawing.Point(720, 37)
$p7bBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
$p7bBrowseButton.Text = "Browse..."


$p7bDataGridView = New-Object System.Windows.Forms.DataGridView
$p7bDataGridView.Location = New-Object System.Drawing.Point(620, 70)
$p7bDataGridView.Size = New-Object System.Drawing.Size(600, 300)
$p7bDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$p7bDataGridView.AllowUserToAddRows = $false
$p7bDataGridView.ReadOnly = $true;
$p7bDataGridView.SelectionMode = "FullRowSelect"
$p7bDataGridView.MultiSelect = $false;

# --- Action Buttons ---
$replaceButton = New-Object System.Windows.Forms.Button
$replaceButton.Location = New-Object System.Drawing.Point(10, 380)
$replaceButton.Size = New-Object System.Drawing.Size(150, 30)
$replaceButton.Text = "Replace Certificate"
$replaceButton.Enabled = $false

$createChainButton = New-Object System.Windows.Forms.Button
$createChainButton.Location = New-Object System.Drawing.Point(170, 380)
$createChainButton.Size = New-Object System.Drawing.Size(150, 30)
$createChainButton.Text = "Create Chain"
$createChainButton.Enabled = $false

$cleanupButton = New-Object System.Windows.Forms.Button
$cleanupButton.Location = New-Object System.Drawing.Point(330, 380)
$cleanupButton.Size = New-Object System.Drawing.Size(150, 30)
$cleanupButton.Text = "Cleanup Keystore"
$cleanupButton.Enabled = $false

# --- Information Textbox ---
$infoTextBox = New-Object System.Windows.Forms.TextBox
$infoTextBox.Location = New-Object System.Drawing.Point(10, 420)
$infoTextBox.Size = New-Object System.Drawing.Size(1210, 100)  # Wider
$infoTextBox.Multiline = $true
$infoTextBox.ReadOnly = $true
$infoTextBox.ScrollBars = "Vertical"
$infoTextBox.Visible = $false #Hidden initially.

# --- Form Shown Event ---
$form.add_Shown({
    $form.Invoke([Action]{
        if ($keystoreDataGridView.Columns.Contains("PrivateKey")) {
            $keystoreDataGridView.Columns["PrivateKey"].Visible = $false
        }
        $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)
    })
})

# --- Event Handlers ---

$keystoreOpenButton.Add_Click({
    if ([string]::IsNullOrEmpty($keystoreTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a keystore file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }
     $infoMessages.Clear() #clear messages
     $infoTextBox.Visible = $false #hide
    $securePassword = Get-KeystorePassword
    if ($securePassword) {
        $keystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $securePassword
        if ($keystoreCerts) {
            $keystoreCertificates.Clear()
            $keystoreDataTable = New-Object System.Data.DataTable
            $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
            $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
            $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null

            foreach ($cert in $keystoreCerts) {
                $row = $keystoreDataTable.NewRow()
                $row.Subject = $cert.Subject
                $row.Issuer = $cert.Issuer
                $row.NotBefore = $cert.NotBefore
                $row.NotAfter = $cert.NotAfter
                $row.Thumbprint = $cert.Thumbprint
                $row.SerialNumber = $cert.SerialNumber
                $row.SKI = Get-CertificateSKI $cert
                $keystoreDataTable.Rows.Add($row)
                $keystoreCertificates.Add($cert) | Out-Null
            }
            $keystoreDataGridView.DataSource = $keystoreDataTable
        }
        $securePassword.Dispose()
        Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
        $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    }
    $replaceButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    $createChainButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)

})


$p7bBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $p7bTextBox.Text = $OpenFileDialog.FileName
        $infoMessages.Clear() #clear messages
        $infoTextBox.Visible = $false #hide
        $p7bCerts = Get-P7BCertificates -P7BPath $p7bTextBox.Text
        if ($p7bCerts) {
            $p7bCertificates.Clear()
            $p7bDataTable = New-Object System.Data.DataTable
            $p7bDataTable.Columns.Add("Subject", [string]) | Out-Null
            $p7bDataTable.Columns.Add("Issuer", [string]) | Out-Null
            $p7bDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
            $p7bDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
            $p7bDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
            $p7bDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
            $p7bDataTable.Columns.Add("SKI", [string]) | Out-Null

            foreach ($cert in $p7bCerts) {
                $row = $p7bDataTable.NewRow()
                $row.Subject = $cert.Subject
                $row.Issuer = $cert.Issuer
                $row.NotBefore = $cert.NotBefore
                $row.NotAfter = $cert.NotAfter
                $row.Thumbprint = $cert.Thumbprint
                $row.SerialNumber = $cert.SerialNumber
                $row.SKI = Get-CertificateSKI $cert
                $p7bDataTable.Rows.Add($row)
                $p7bCertificates.Add($cert) | Out-Null
            }
            $p7bDataGridView.DataSource = $p7bDataTable
        }
        Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
         $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    }
    $replaceButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    $createChainButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
    $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)
})


$keystoreBrowseButton.Add_Click({
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "Keystore files (*.p12;*.pfx)|*.p12;*.pfx"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $keystoreTextBox.Text = $OpenFileDialog.FileName
    }
})



$replaceButton.Add_Click({
    $selectedKeystoreIndex = $keystoreDataGridView.SelectedRows[0].Index
    $selectedP7BIndex = $p7bDataGridView.SelectedRows[0].Index
    $selectedKeystoreCert = $keystoreCertificates[$selectedKeystoreIndex]
    $selectedP7BCert = $p7bCertificates[$selectedP7BIndex]

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
                        $keystoreCertificates.Clear()
                         $keystoreDataTable = New-Object System.Data.DataTable
                        $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
                         $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null
                        foreach ($cert in $updatedKeystoreCerts) {
                            $row = $keystoreDataTable.NewRow()
                            $row.Subject = $cert.Subject
                            $row.Issuer = $cert.Issuer
                            $row.NotBefore = $cert.NotBefore
                            $row.NotAfter = $cert.NotAfter
                            $row.Thumbprint = $cert.Thumbprint
                            $row.SerialNumber = $cert.SerialNumber
                            $row.SKI = Get-CertificateSKI $cert
                            $keystoreDataTable.Rows.Add($row)
                            $keystoreCertificates.Add($cert) | Out-Null
                        }
                        $keystoreDataGridView.DataSource = $keystoreDataTable
                        Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
                        $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
                    }
                }

            }
        }
    }
    else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and one from P7B to replace.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    #Keep enabled status
})

$createChainButton.Add_Click({
    $selectedKeystoreIndex = $keystoreDataGridView.SelectedRows[0].Index
    $selectedKeystoreCert = $keystoreCertificates[$selectedKeystoreIndex]
    $p7bCerts = $p7bDataGridView.DataSource

    if($selectedKeystoreCert -and $p7bCerts -is [System.Data.DataTable])
    {
        $intermediateCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        foreach($cert in $p7bCertificates)
        {
            $intermediateCerts.Add($cert)
        }

        $securePassword = Get-KeystorePassword
        if($securePassword)
        {
            Build-CertificateChain -LeafCertificate $selectedKeystoreCert -IntermediateCertificates $intermediateCerts -KeystorePassword $securePassword
             $securePassword.Dispose()
        }
    }
     else
    {
        [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and ensure the P7B is loaded.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
     #Keep enabled status.

})

$cleanupButton.Add_Click({
    $securePassword = Get-KeystorePassword
    if ($securePassword) {
       $result = Cleanup-Keystore -KeystorePath $keystoreTextBox.Text -KeystorePassword $securePassword -KeystoreCertificates $keystoreCertificates -P7BCertificates $p7bCertificates
       $securePassword.Dispose()

        if($result){
            $refreshSecurePassword = Get-KeystorePassword
                if($refreshSecurePassword)
                {
                    $updatedKeystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $refreshSecurePassword
                    $refreshSecurePassword.Dispose()
                    if ($updatedKeystoreCerts) {
                        $keystoreCertificates.Clear()
                         $keystoreDataTable = New-Object System.Data.DataTable
                        $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
                         $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null
                        foreach ($cert in $updatedKeystoreCerts) {
                            $row = $keystoreDataTable.NewRow()
                            $row.Subject = $cert.Subject
                            $row.Issuer = $cert.Issuer
                            $row.NotBefore = $cert.NotBefore
                            $row.NotAfter = $cert.NotAfter
                            $row.Thumbprint = $cert.Thumbprint
                            $row.SerialNumber = $cert.SerialNumber
                            $row.SKI = Get-CertificateSKI $cert
                            $keystoreDataTable.Rows.Add($row)
                            $keystoreCertificates.Add($cert) | Out-Null
                        }
                        $keystoreDataGridView.DataSource = $keystoreDataTable
                        Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
                        $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
                    }
                }
        }
    }
    #Keep enabled status.
})


$keystoreDataGridView.add_SelectionChanged({
  #Keep Enabled Status.
})

$p7bDataGridView.add_SelectionChanged({
    #Keep Enabled Status.
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
$form.Controls.Add($cleanupButton)
$form.Controls.Add($infoTextBox)

# --- Show the Form ---
$form.ShowDialog()
