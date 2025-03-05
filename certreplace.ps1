# Requires -Modules @{ ModuleName = 'PKI'; ModuleVersion = '1.0.0.0' }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Runtime.InteropServices

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

function Show-Certificate {
    param (
        [System.Windows.Forms.DataGridView]$DataGridView,
        [System.Collections.ArrayList]$MatchingSKIs
    )

    foreach ($row in $DataGridView.Rows) {
      if ($row.DataBoundItem) {
        # Check the type and cast appropriately
        if ($row.DataBoundItem -is [System.Data.DataRowView]) {
            $dataRow = $row.DataBoundItem.Row  # Access the underlying DataRow

            # Check for expiration by accessing columns by name
            if ($dataRow.Table.Columns.Contains("NotAfter") -and $dataRow.Table.Columns.Contains("NotBefore")) {
                if ($dataRow["NotAfter"] -lt [DateTime]::Now -or $dataRow["NotBefore"] -gt [DateTime]::Now) {
                    $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
                }
            }

            # Check for matching SKIs
            if ($dataRow.Table.Columns.Contains("SKI")) {
                $ski = $dataRow["SKI"]
                if ($ski -and $MatchingSKIs.Contains($ski)) {
                    $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
                }
            }
        }
      }
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
        $keystore.Import($KeystorePath, $passwordString, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

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

    # Get the DataTables from the DataGridViews
    $keystoreData = $KeystoreDataGridView.DataSource
    $p7bData = $P7bDataGridView.DataSource

    if ($keystoreData -is [System.Data.DataTable] -and $p7bData -is [System.Data.DataTable]) {
        $matchingSKIs = New-Object System.Collections.ArrayList

        # Iterate through the rows of the keystore DataTable
        foreach ($keystoreRow in $keystoreData.Rows) {
            $keystoreSKI = $keystoreRow["SKI"]
            if ($keystoreSKI) {
                # Iterate through the rows of the P7B DataTable
                foreach ($p7bRow in $p7bData.Rows) {
                    $p7bSKI = $p7bRow["SKI"]
                    if ($p7bSKI -and $keystoreSKI -eq $p7bSKI) {
                        $matchingSKIs.Add($keystoreSKI) | Out-Null
                        break  # No need to continue inner loop
                    }
                }
            }
        }

        # Call Show-Certificate with DataGridViews and matching SKIs
        Show-Certificate -DataGridView $KeystoreDataGridView -MatchingSKIs $matchingSKIs
        Show-Certificate -DataGridView $P7bDataGridView -MatchingSKIs $matchingSKIs
    }
    else {
        # Clear any previous highlighting if one of the DataGridViews is empty
        Show-Certificate -DataGridView $KeystoreDataGridView -MatchingSKIs @()
        Show-Certificate -DataGridView $P7bDataGridView -MatchingSKIs @()
    }
}

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

# --- Form Shown Event (CRITICAL FIX) ---
$form.add_Shown({
    # Use Invoke to ensure UI updates happen on the correct thread.
    $form.Invoke([Action]{
        if ($keystoreDataGridView.Columns.Contains("PrivateKey")) {
            $keystoreDataGridView.Columns["PrivateKey"].Visible = $false
        }
    })
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
              # Create a DataTable for the keystore certificates
            $keystoreDataTable = New-Object System.Data.DataTable
            $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
            $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
            $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
            $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null # Add SKI column


            # Populate the DataTable
            foreach ($cert in $keystoreCerts) {
                $row = $keystoreDataTable.NewRow()
                $row.Subject = $cert.Subject
                $row.Issuer = $cert.Issuer
                $row.NotBefore = $cert.NotBefore
                $row.NotAfter = $cert.NotAfter
                $row.Thumbprint = $cert.Thumbprint
                $row.SerialNumber = $cert.SerialNumber
                $row.SKI = Get-CertificateSKI $cert  # Extract and add SKI
                $keystoreDataTable.Rows.Add($row)
            }
            $keystoreDataGridView.DataSource = $keystoreDataTable
        }
        $securePassword.Dispose()
    }
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
            # Create DataTable for P7B certificates
            $p7bDataTable = New-Object System.Data.DataTable
            $p7bDataTable.Columns.Add("Subject", [string]) | Out-Null
            $p7bDataTable.Columns.Add("Issuer", [string]) | Out-Null
            $p7bDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
            $p7bDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
            $p7bDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
            $p7bDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
            $p7bDataTable.Columns.Add("SKI", [string]) | Out-Null # Add SKI Column

            foreach ($cert in $p7bCerts) {
                $row = $p7bDataTable.NewRow()
                $row.Subject = $cert.Subject
                $row.Issuer = $cert.Issuer
                $row.NotBefore = $cert.NotBefore
                $row.NotAfter = $cert.NotAfter
                $row.Thumbprint = $cert.Thumbprint
                $row.SerialNumber = $cert.SerialNumber
                $row.SKI = Get-CertificateSKI $cert # Extract and add SKI.
                $p7bDataTable.Rows.Add($row)
            }
            $p7bDataGridView.DataSource = $p7bDataTable
        }
    }
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
                         # Create a DataTable for the keystore certificates
                        $keystoreDataTable = New-Object System.Data.DataTable
                        $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
                        $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
                        $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
                         $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null

                        # Populate the DataTable
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
                        }
                        $keystoreDataGridView.DataSource = $keystoreDataTable
                        Compare-Certificates  -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
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
