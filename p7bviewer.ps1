Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "P7B Viewer"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"

# Create a TextBox for the file path
$filePathTextBox = New-Object System.Windows.Forms.TextBox
$filePathTextBox.Location = New-Object System.Drawing.Point(10, 10)
$filePathTextBox.Size = New-Object System.Drawing.Size(650, 20)
$filePathTextBox.ReadOnly = $true  # User can't type directly, only browse
$form.Controls.Add($filePathTextBox)

# Create a Browse button
$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Location = New-Object System.Drawing.Point(670, 7)
$browseButton.Size = New-Object System.Drawing.Size(100, 23)
$browseButton.Text = "Browse..."
$form.Controls.Add($browseButton)

# Create a DataGridView to display the certificates
$dataGridView = New-Object System.Windows.Forms.DataGridView
$dataGridView.Location = New-Object System.Drawing.Point(10, 40)
$dataGridView.Size = New-Object System.Drawing.Size(760, 500)
$dataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$dataGridView.ReadOnly = $true
$dataGridView.AllowUserToAddRows = $false
$form.Controls.Add($dataGridView)



# Function to load certificates from a P7B file
function Get-P7BCertificates {
    param (
        [string]$P7BPath
    )

    try {
        $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $p7b.Import($P7BPath)  # No password needed for P7B
        return $p7b
    }
    catch {
        Write-Warning "Error opening P7B file: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}


# Event handler for the Browse button
$browseButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $filePathTextBox.Text = $openFileDialog.FileName

        # Load and display certificates
        $certificates = Get-P7BCertificates -P7BPath $filePathTextBox.Text
        if ($certificates) {
            $dataGridView.DataSource = $certificates
        }
    }
})

# Show the form
$form.ShowDialog()
