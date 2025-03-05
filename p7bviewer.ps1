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
$filePathTextBox.ReadOnly = $true
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
$dataGridView.ReadOnly = $true
$dataGridView.AllowUserToAddRows = $false
$dataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$form.Controls.Add($dataGridView)

# Function to load certificates from a P7B file
function Get-P7BCertificates {
    param (
        [string]$P7BPath
    )

    try {
        $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $p7b.Import($P7BPath)
        Write-Host "Successfully imported P7B file: $P7BPath" -ForegroundColor Green
        return $p7b
    }
    catch {
        $errorMessage = "Error opening P7B file: $($_.Exception.Message)"
        Write-Warning $errorMessage
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

# Event handler for the Browse button
$browseButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $filePathTextBox.Text = $openFileDialog.FileName
        Write-Host "Selected file: $($filePathTextBox.Text)"

        # Load certificates
        $certificates = Get-P7BCertificates -P7BPath $filePathTextBox.Text

        if ($certificates) {
            Write-Host "Number of certificates loaded: $($certificates.Count)" -ForegroundColor Green

            try {
                # Select specific properties
                $displayData = $certificates | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint, SerialNumber

                if ($displayData) {
                    Write-Host "Data to be displayed (first item): $($displayData[0] | Format-List | Out-String)" -ForegroundColor Cyan

                    # Create a DataTable and populate it (more robust)
                    $dataTable = New-Object System.Data.DataTable
                    $dataTable.Columns.Add("Subject", [string]) | Out-Null
                    $dataTable.Columns.Add("Issuer", [string]) | Out-Null
                    $dataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
                    $dataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
                    $dataTable.Columns.Add("Thumbprint", [string]) | Out-Null
                    $dataTable.Columns.Add("SerialNumber", [string]) | Out-Null


                    foreach ($item in $displayData) {
                        $row = $dataTable.NewRow()
                        $row.Subject = $item.Subject
                        $row.Issuer = $item.Issuer
                        $row.NotBefore = $item.NotBefore
                        $row.NotAfter = $item.NotAfter
                        $row.Thumbprint = $item.Thumbprint
                        $row.SerialNumber = $item.SerialNumber
                        $dataTable.Rows.Add($row)
                    }

                    $dataGridView.DataSource = $dataTable  # Bind the DataTable


                    if($dataGridView.Columns.Count -gt 0) {
                        Write-Host "DataGridView columns populated. Count: $($dataGridView.Columns.Count)" -ForegroundColor Green
                    }
                    else
                    {
                        Write-Warning "DataGridView has no columns after setting DataSource."
                    }
                } else {
                    Write-Warning "Select-Object returned no data."
                    [System.Windows.Forms.MessageBox]::Show("No certificate data to display.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                }
            }
            catch {
                $errorMessage = "Error displaying certificates: $($_.Exception.Message)"
                Write-Warning $errorMessage
                [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
        else {
             Write-Warning "No certificates loaded."
        }
    }
})
# Show the form
$form.ShowDialog()
