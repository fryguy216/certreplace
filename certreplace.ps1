1 # Requires -Modules @{ ModuleName = 'PKI'; ModuleVersion = '1.0.0.0' }
  2
  3 Add-Type -AssemblyName System.Windows.Forms
  4 Add-Type -AssemblyName System.Drawing
  5 Add-Type -AssemblyName System.Runtime.InteropServices
  6
  7 # --- Global Variables ---
  8 $keystoreCertificates = New-Object System.Collections.ArrayList
  9 $p7bCertificates = New-Object System.Collections.ArrayList
 10 $infoMessages = New-Object System.Collections.ArrayList #For info messages.
 11
 12 # --- Functions ---
 13
 14 function Get-KeystorePassword {
 15     $form = New-Object System.Windows.Forms.Form -Property @{
 16         Text          = "Enter Keystore Password"
 17         Size          = New-Object System.Drawing.Size(300, 150)
 18         StartPosition = "CenterScreen"
 19     }
 20
 21     $label = New-Object System.Windows.Forms.Label -Property @{
 22         Location = New-Object System.Drawing.Point(10, 20)
 23         Size     = New-Object System.Drawing.Size(280, 20)
 24         Text     = "Password:"
 25     }
 26     $form.Controls.Add($label)
 27
 28     $textBox = New-Object System.Windows.Forms.TextBox -Property @{
 29         Location   = New-Object System.Drawing.Point(10, 40)
 30         Size       = New-Object System.Drawing.Size(260, 20)
 31         PasswordChar = "*"
 32     }
 33     $form.Controls.Add($textBox)
 34
 35     $okButton = New-Object System.Windows.Forms.Button -Property @{
 36         Location = New-Object System.Drawing.Point(130, 80)
 37         Size     = New-Object System.Drawing.Size(75, 23)
 38         Text     = "OK"
 39         DialogResult = [System.Windows.Forms.DialogResult]::OK
 40     }
 41     $form.Controls.Add($okButton)
 42     $form.AcceptButton = $okButton
 43
 44     $cancelButton = New-Object System.Windows.Forms.Button -Property @{
 45         Location     = New-Object System.Drawing.Point(210, 80)
 46         Size         = New-Object System.Drawing.Size(75, 23)
 47         Text         = "Cancel"
 48         DialogResult = [System.Windows.Forms.DialogResult]::Cancel
 49     }
 50     $form.Controls.Add($cancelButton)
 51     $form.CancelButton = $cancelButton
 52
 53     $result = $form.ShowDialog()
 54
 55     if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
 56         $securePassword = New-Object System.Security.SecureString
 57         foreach ($char in $textBox.Text.ToCharArray()) {
 58             $securePassword.AppendChar($char)
 59         }
 60         return $securePassword
 61     }
 62     else {
 63         return $null
 64     }
 65     $form.Dispose()
 66 }
 67
 68 function Get-KeystoreCertificates {
 69     param (
 70         [string]$KeystorePath,
 71         [System.Security.SecureString]$Password
 72     )
 73
 74     try {
 75         $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
 76         $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
 77         $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
 78         $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
 79         $keystore.Import($KeystorePath, $passwordString, $flags)
 80         return $keystore
 81     }
 82     catch {
 83         Write-Warning "Error opening keystore: $($_.Exception.Message)"
 84         [System.Windows.Forms.MessageBox]::Show("Error opening keystore: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
 85         return $null
 86     }
 87     finally {
 88         if ($bstr) {
 89             [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
 90         }
 91         if($Password){
 92             $Password.Dispose()
 93         }
 94     }
 95 }
 96
 97 function Get-P7BCertificates {
 98     param (
 99         [string]$P7BPath
100     )
101
102     try {
103         $p7b = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
104         $p7b.Import($P7BPath)
105         return $p7b
106     }
107     catch {
108         Write-Warning "Error opening P7B file: $($_.Exception.Message)"
109         [System.Windows.Forms.MessageBox]::Show("Error opening P7B file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
110         return $null
111     }
112 }
113
114 function Get-CertificateSKI {
115     param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
116
117     $skiExtension = $Certificate.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.14"}
118     if ($skiExtension) {
119         return $skiExtension.Format(0)
120     }
121     return $null
122 }
123
124 function Set-KeystoreCertificate {
125     param(
126         [string]$KeystorePath,
127         [System.Security.SecureString]$KeystorePassword,
128         [System.Security.Cryptography.X509Certificates.X509Certificate2]$OldCertificate,
129         [System.Security.Cryptography.X509Certificates.X509Certificate2]$NewCertificate
130     )
131
132     $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
133     $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
134
135     try {
136         $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
137         $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor
138                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
139                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
140         $keystore.Import($KeystorePath, $passwordString, $flags)
141
142
143         $indexToReplace = -1
144         for ($i = 0; $i -lt $keystore.Count; $i++) {
145             if ($keystore[$i].Thumbprint -eq $OldCertificate.Thumbprint) {
146                 $indexToReplace = $i
147                 break
148             }
149         }
150
151         if ($indexToReplace -eq -1) {
152             Write-Warning "The certificate to be replaced was not found in the keystore."
153              [System.Windows.Forms.MessageBox]::Show("The certificate to be replaced was not found in the keystore.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
154             return $false
155         }
156         $keystore.RemoveAt($indexToReplace)
157         $keystore.Add($NewCertificate)
158
159         $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
160         [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)
161
162         Write-Host "Certificate replaced successfully." -ForegroundColor Green
163         [System.Windows.Forms.MessageBox]::Show("Certificate replaced successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
164         return $true
165     }
166     catch {
167         $errorMessage = "Error replacing certificate: $($_.Exception.Message)"
168         Write-Warning $errorMessage
169         [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
170         return $false
171     }
172     finally {
173         if ($bstr) {
174             [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
175         }
176         if($KeystorePassword){
177             $KeystorePassword.Dispose()
178         }
179     }
180 }
181
182 function Build-CertificateChain {
183     param (
184         [System.Security.Cryptography.X509Certificates.X509Certificate2]$LeafCertificate,
185         [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$IntermediateCertificates,
186         [System.Security.SecureString]$KeystorePassword
187     )
188
189     $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
190     $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
191
192     try {
193         $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
194         $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
195         $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
196         $chain.ChainPolicy.ExtraStore.AddRange($IntermediateCertificates)
197
198         if ($chain.Build($LeafCertificate)) {
199             $chainedCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
200             $chainedCerts.Add($LeafCertificate)
201
202             foreach ($element in $chain.ChainElements) {
203                  if ($element.Certificate.Thumbprint -ne $LeafCertificate.Thumbprint)
204                  {
205                     $chainedCerts.Add($element.Certificate)
206                  }
207             }
208
209             $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
210             $SaveFileDialog.Filter = "PFX files (*.pfx)|*.pfx"
211             $SaveFileDialog.Title = "Save Chained Certificate As"
212             $SaveFileDialog.FileName = "chained_certificate.pfx"
213             if ($SaveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
214                 $outputPath = $SaveFileDialog.FileName
215                  $pfxBytes = $chainedCerts.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
216                  [System.IO.File]::WriteAllBytes($outputPath, $pfxBytes)
217                 Write-Host "Certificate chain saved to: $outputPath" -ForegroundColor Green
218                 [System.Windows.Forms.MessageBox]::Show("Certificate chain saved to: $outputPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
219             }
220         }
221         else {
222             Write-Warning "Failed to build a valid certificate chain."
223             [System.Windows.Forms.MessageBox]::Show("Failed to build a valid certificate chain.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
224             Write-Host "Chain Status:" -ForegroundColor Yellow
225             foreach($status in $chain.ChainStatus){
226                 Write-Host ("  " + $status.StatusInformation) -ForegroundColor Yellow
227             }
228         }
229     }
230     catch {
231         Write-Warning "Error building certificate chain: $($_.Exception.Message)"
232         [System.Windows.Forms.MessageBox]::Show("Error building certificate chain: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
233     }
234     finally{
235         if ($chain -ne $null){
236             $chain.Reset()
237         }
238         if ($bstr) {
239             [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
240         }
241          if($KeystorePassword){
242             $KeystorePassword.Dispose()
243         }
244     }
245 }
246
247 function Compare-Certificates {
248   param (
249         [System.Windows.Forms.DataGridView]$KeystoreDataGridView,
250         [System.Windows.Forms.DataGridView]$P7bDataGridView
251     )
252
253   # Clear previous messages
254   $infoMessages.Clear()
255
256   $keystoreData = $KeystoreDataGridView.DataSource
257   $p7bData = $P7bDataGridView.DataSource
258
259     if ($keystoreData -is [System.Data.DataTable] -and $p7bData -is [System.Data.DataTable]) {
260         # --- Check for duplicate SKIs in keystore ---
261         $skiCounts = @{}
262         foreach ($row in $keystoreData.Rows) {
263             $ski = $row["SKI"]
264             if ($ski) {
265                 if (!$skiCounts.ContainsKey($ski)) {
266                     $skiCounts[$ski] = 0
267                 }
268                 $skiCounts[$ski]++
269             }
270         }
271         foreach($ski in $skiCounts.Keys){
272             if($skiCounts[$ski] -gt 1){
273                  $infoMessages.Add("Keystore contains duplicate certificates, dedupe recommended") | Out-Null
274                  break; #only add once.
275             }
276         }
277
278         # --- Check for expired certificates in keystore ---
279         foreach ($row in $keystoreData.Rows) {
280           if ($row["NotAfter"] -lt [DateTime]::Now -or $row["NotBefore"] -gt [DateTime]::Now) {
281             $infoMessages.Add("Keystore contains expired certificates, replacement recommended") | Out-Null
282             break;  # Only need one message
283           }
284         }
285
286         # --- Check for newer certificates in P7B ---
287         foreach ($keystoreRow in $keystoreData.Rows) {
288             $keystoreSKI = $keystoreRow["SKI"]
289             $keystoreNotAfter = $keystoreRow["NotAfter"]
290             if ($keystoreSKI -and $keystoreNotAfter) {
291                 foreach ($p7bRow in $p7bData.Rows) {
292                     $p7bSKI = $p7bRow["SKI"]
293                     $p7bNotAfter = $p7bRow["NotAfter"]
294                     if ($p7bSKI -and $keystoreSKI -eq $p7bSKI -and $p7bNotAfter -gt $keystoreNotAfter) {
295                         $infoMessages.Add("P7B contains newer certificates than those in the keystore, replacement recommended") | Out-Null
296                          break 2  # exit both loops after first
297                     }
298                 }
299             }
300         }
301
302          # --- Check if P7B has valid chain for personal certs ---
303         if($p7bData){
304             foreach ($keystoreRow in $keystoreData.Rows)
305             {
306                 $keystoreSKI = $keystoreRow["SKI"]
307                 # Find the personal certificate
308                 if ($keystoreSKI) {
309                    $personalCert = $keystoreCertificates.Where({(Get-CertificateSKI $_) -eq $keystoreSKI}, 'First')
310                    if($personalCert){
311                         $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
312                         $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
313                         $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
314                         $intermediateCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
315                          foreach($cert in $p7bCertificates)
316                         {
317                             $intermediateCerts.Add($cert)
318                         }
319                         $chain.ChainPolicy.ExtraStore.AddRange($intermediateCerts)
320
321                         if($chain.Build($personalCert)){
322                              if($chain.ChainElements.Count -gt 1){
323                                 $infoMessages.Add("P7B contains newer certificates than a personal certificate in the keystore, chain rebuild recommended.") | Out-Null;
324                                 break; #exit on first match
325                              }
326                         }
327                         $chain.Reset()
328                    }
329                 }
330             }
331         }
332     }
333
334     # Update the information textbox
335     $infoTextBox.Text = [string]::Join([Environment]::NewLine, $infoMessages)
336 }
337
338
339 function Cleanup-Keystore {
340     param(
341         [string]$KeystorePath,
342         [System.Security.SecureString]$KeystorePassword,
343         [System.Collections.ArrayList]$KeystoreCertificates,
344         [System.Collections.ArrayList]$P7BCertificates
345     )
346
347     $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeystorePassword)
348     $passwordString = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
349
350     try {
351         $keystore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
352         $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet -bor
353                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
354                  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
355         $keystore.Import($KeystorePath, $passwordString, $flags)
356
357         # --- 1. Remove Duplicate SKIs (Keep Latest Expiry) ---
358
359         $skiGroups = @{}
360         foreach ($cert in $KeystoreCertificates) {
361             $ski = Get-CertificateSKI $cert
362             if ($ski) {
363                 if (!$skiGroups.ContainsKey($ski)) {
364                     $skiGroups[$ski] = New-Object System.Collections.ArrayList
365                 }
366                 $skiGroups[$ski].Add($cert)
367             }
368         }
369
370         $certsToRemove = New-Object System.Collections.ArrayList
371         foreach ($ski in $skiGroups.Keys) {
372             $group = $skiGroups[$ski]
373             if ($group.Count -gt 1) {
374                 # Sort by NotAfter (descending - latest first)
375                 $sortedGroup = $group | Sort-Object -Property NotAfter -Descending
376                 # Keep the first (latest), mark the rest for removal
377                 for ($i = 1; $i -lt $sortedGroup.Count; $i++) {
378                     $certsToRemove.Add($sortedGroup[$i]) | Out-Null
379                 }
380             }
381         }
382
383         foreach ($certToRemove in $certsToRemove) {
384              Write-Host "Removing duplicate certificate (by SKI): $($certToRemove.Subject)" -ForegroundColor Yellow
385             $keystore.Remove($certToRemove)
386             $KeystoreCertificates.Remove($certToRemove) | Out-Null
387         }
388
389
390         # --- 2. Remove and Replace with P7B Matches ---
391         $certsToRemove = New-Object System.Collections.ArrayList
392         foreach ($keystoreCert in $KeystoreCertificates) {
393             $keystoreSKI = Get-CertificateSKI $keystoreCert
394             foreach($p7bCert in $P7BCertificates){
395                 $p7bSKI = Get-CertificateSKI $p7bCert
396                 if($keystoreSKI -eq $p7bSKI){
397                     $certsToRemove.Add($keystoreCert) | Out-Null
398                     Write-Host "Replacing certificate with P7B match (by SKI): $($keystoreCert.Subject)" -ForegroundColor Yellow
399                     $keystore.Remove($keystoreCert)
400                     $keystore.Add($p7bCert)
401                     #Update the ArrayList
402                     $KeystoreCertificates.Remove($keystoreCert) | Out-Null
403                     $found = $false;
404                     foreach($existingp7b in $P7bCertificates){
405                         if($existingp7b.Thumbprint -eq $p7bCert.Thumbprint){
406                             $found = $true;
407                             break;
408                         }
409                     }
410                     if(-not $found){
411                         $P7bCertificates.Add($p7bCert) | Out-Null
412                     }
413
414                     break
415                 }
416             }
417         }
418
419         # --- 3. Chain Management ---
420
421        foreach($personalCert in $KeystoreCertificates){
422             $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
423             $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
424             $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
425             $intermediateCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
426              foreach($cert in $P7bCertificates)
427             {
428                 $intermediateCerts.Add($cert)
429             }
430             $chain.ChainPolicy.ExtraStore.AddRange($intermediateCerts)
431
432             if($chain.Build($personalCert)){
433                 #Chain is Valid, proceed
434                 if($chain.ChainElements.Count -gt 1){
435                     #It's a real chain, remove from keystore.
436                      Write-Host "Rebuilding Chain For: $($personalCert.Subject)" -ForegroundColor Yellow
437                     for($i = 1; $i -lt $chain.ChainElements.Count - 1; $i++){  # The last element is the root, don't remove
438                         $certToRemove = $chain.ChainElements[$i].Certificate
439                         $keystore.Remove($certToRemove)
440                         $KeystoreCertificates.Remove($certToRemove) | Out-Null
441                     }
442                 }
443
444             }
445             $chain.Reset()
446        }
447
448
449         # --- Save Modified Keystore ---
450         $keystoreBytes = $keystore.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $passwordString)
451         [System.IO.File]::WriteAllBytes($KeystorePath, $keystoreBytes)
452
453         Write-Host "Keystore cleanup complete." -ForegroundColor Green
454         [System.Windows.Forms.MessageBox]::Show("Keystore cleanup complete.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
455          return $true
456     }
457     catch {
458         $errorMessage = "Error during keystore cleanup: $($_.Exception.Message)"
459         Write-Warning $errorMessage
460         [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
461         return $false
462     }
463     finally {
464         if ($bstr) {
465             [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
466         }
467         if ($KeystorePassword) {
468             $KeystorePassword.Dispose()
469         }
470     }
471 }
472
473 # --- GUI Setup ---
474
475 $form = New-Object System.Windows.Forms.Form
476 $form.Text = "Keystore and P7B Certificate Comparator"
477 $form.Size = New-Object System.Drawing.Size(1250, 600)
478 $form.StartPosition = "CenterScreen"
479
480 # --- Keystore Controls ---
481
482 $keystoreLabel = New-Object System.Windows.Forms.Label
483 $keystoreLabel.Location = New-Object System.Drawing.Point(10, 10)
484 $keystoreLabel.Size = New-Object System.Drawing.Size(100, 20)
485 $keystoreLabel.Text = "Keystore File:"
486
487 $keystoreTextBox = New-Object System.Windows.Forms.TextBox
488 $keystoreTextBox.Location = New-Object System.Drawing.Point(110, 10)
489 $keystoreTextBox.Size = New-Object System.Drawing.Size(400, 20)
490 $keystoreTextBox.ReadOnly = $true
491
492 $keystoreBrowseButton = New-Object System.Windows.Forms.Button
493 $keystoreBrowseButton.Location = New-Object System.Drawing.Point(520, 7)
494 $keystoreBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
495 $keystoreBrowseButton.Text = "Browse..."
496
497 $keystoreOpenButton = New-Object System.Windows.Forms.Button
498 $keystoreOpenButton.Location = New-Object System.Drawing.Point(110, 40)
499 $keystoreOpenButton.Size = New-Object System.Drawing.Size(75, 23)
500 $keystoreOpenButton.Text = "Open"
501
502 $keystoreDataGridView = New-Object System.Windows.Forms.DataGridView
503 $keystoreDataGridView.Location = New-Object System.Drawing.Point(10, 70)
504 $keystoreDataGridView.Size = New-Object System.Drawing.Size(600, 300)
505 $keystoreDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
506 $keystoreDataGridView.AllowUserToAddRows = $false
507 $keystoreDataGridView.ReadOnly = $true;
508 $keystoreDataGridView.SelectionMode = "FullRowSelect"
509 $keystoreDataGridView.MultiSelect = $false;
510
511 # --- P7B Controls ---
512
513 $p7bLabel = New-Object System.Windows.Forms.Label
514 $p7bLabel.Location = New-Object System.Drawing.Point(620, 10)
515 $p7bLabel.Size = New-Object System.Drawing.Size(100, 20)
516 $p7bLabel.Text = "P7B File:"
517
518 $p7bTextBox = New-Object System.Windows.Forms.TextBox
519 $p7bTextBox.Location = New-Object System.Drawing.Point(720, 10)
520 $p7bTextBox.Size = New-Object System.Drawing.Size(400, 20)
521 $p7bTextBox.ReadOnly = $true
522
523 $p7bBrowseButton = New-Object System.Windows.Forms.Button
524 $p7bBrowseButton.Location = New-Object System.Drawing.Point(720, 37)
525 $p7bBrowseButton.Size = New-Object System.Drawing.Size(75, 23)
526 $p7bBrowseButton.Text = "Browse..."
527
528
529 $p7bDataGridView = New-Object System.Windows.Forms.DataGridView
530 $p7bDataGridView.Location = New-Object System.Drawing.Point(620, 70)
531 $p7bDataGridView.Size = New-Object System.Drawing.Size(600, 300)
532 $p7bDataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
533 $p7bDataGridView.AllowUserToAddRows = $false
534 $p7bDataGridView.ReadOnly = $true;
535 $p7bDataGridView.SelectionMode = "FullRowSelect"
536 $p7bDataGridView.MultiSelect = $false;
537
538 # --- Action Buttons ---
539 $replaceButton = New-Object System.Windows.Forms.Button
540 $replaceButton.Location = New-Object System.Drawing.Point(10, 380)
541 $replaceButton.Size = New-Object System.Drawing.Size(150, 30)
542 $replaceButton.Text = "Replace Certificate"
543 $replaceButton.Enabled = $false
544
545 $createChainButton = New-Object System.Windows.Forms.Button
546 $createChainButton.Location = New-Object System.Drawing.Point(170, 380)
547 $createChainButton.Size = New-Object System.Drawing.Size(150, 30)
548 $createChainButton.Text = "Create Chain"
549 $createChainButton.Enabled = $false
550
551 $cleanupButton = New-Object System.Windows.Forms.Button
552 $cleanupButton.Location = New-Object System.Drawing.Point(330, 380)
553 $cleanupButton.Size = New-Object System.Drawing.Size(150, 30)
554 $cleanupButton.Text = "Cleanup Keystore"
555 $cleanupButton.Enabled = $false
556
557 # --- Information Textbox ---
558 $infoTextBox = New-Object System.Windows.Forms.TextBox
559 $infoTextBox.Location = New-Object System.Drawing.Point(10, 420)
560 $infoTextBox.Size = New-Object System.Drawing.Size(1210, 100)  # Wider
561 $infoTextBox.Multiline = $true
562 $infoTextBox.ReadOnly = $true
563 $infoTextBox.ScrollBars = "Vertical"
564 $infoTextBox.Visible = $false #Hidden initially.
565
566 # --- Form Shown Event ---
567 $form.add_Shown({
568     $form.Invoke([Action]{
569         if ($keystoreDataGridView.Columns.Contains("PrivateKey")) {
570             $keystoreDataGridView.Columns["PrivateKey"].Visible = $false
571         }
572          $replaceButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
573         $createChainButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
574         $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)
575     })
576 })
577
578 # --- Event Handlers ---
579
580 $keystoreOpenButton.Add_Click({
581     if ([string]::IsNullOrEmpty($keystoreTextBox.Text)) {
582         [System.Windows.Forms.MessageBox]::Show("Please select a keystore file.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
583         return
584     }
585      $infoMessages.Clear() #clear messages
586      $infoTextBox.Visible = $false #hide
587     $securePassword = Get-KeystorePassword
588
589     if ($securePassword) {
590         $keystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $securePassword
591
592         if ($keystoreCerts) {
593             $keystoreCertificates.Clear()
594             $keystoreDataTable = New-Object System.Data.DataTable
595             $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
596             $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
597             $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
598             $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
599             $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
600             $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
601             $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null
602
603             foreach ($cert in $keystoreCerts) {
604                 $row = $keystoreDataTable.NewRow()
605                 $row.Subject = $cert.Subject
606                 $row.Issuer = $cert.Issuer
607                 $row.NotBefore = $cert.NotBefore
608                 $row.NotAfter = $cert.NotAfter
609                 $row.Thumbprint = $cert.Thumbprint
610                 $row.SerialNumber = $cert.SerialNumber
611                 $row.SKI = Get-CertificateSKI $cert
612                 $keystoreDataTable.Rows.Add($row)
613                 $keystoreCertificates.Add($cert) | Out-Null
614             }
615             $keystoreDataGridView.DataSource = $keystoreDataTable
616         }
617         $securePassword.Dispose()
618         Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
619         $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
620     }
621     $replaceButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
622     $createChainButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
623     $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)
624
625 })
626
627
628 $p7bBrowseButton.Add_Click({
629     $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
630     $OpenFileDialog.Filter = "P7B files (*.p7b)|*.p7b"
631     if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
632         $p7bTextBox.Text = $OpenFileDialog.FileName
633         $infoMessages.Clear() #clear messages
634         $infoTextBox.Visible = $false #hide
635         $p7bCerts = Get-P7BCertificates -P7BPath $p7bTextBox.Text
636         if ($p7bCerts) {
637             $p7bCertificates.Clear()
638             $p7bDataTable = New-Object System.Data.DataTable
639             $p7bDataTable.Columns.Add("Subject", [string]) | Out-Null
640             $p7bDataTable.Columns.Add("Issuer", [string]) | Out-Null
641             $p7bDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
642             $p7bDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
643             $p7bDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
644             $p7bDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
645             $p7bDataTable.Columns.Add("SKI", [string]) | Out-Null
646
647             foreach ($cert in $p7bCerts) {
648                 $row = $p7bDataTable.NewRow()
649                 $row.Subject = $cert.Subject
650                 $row.Issuer = $cert.Issuer
651                 $row.NotBefore = $cert.NotBefore
652                 $row.NotAfter = $cert.NotAfter
653                 $row.Thumbprint = $cert.Thumbprint
654                 $row.SerialNumber = $cert.SerialNumber
655                 $row.SKI = Get-CertificateSKI $cert
656                 $p7bDataTable.Rows.Add($row)
657                 $p7bCertificates.Add($cert) | Out-Null
658             }
659             $p7bDataGridView.DataSource = $p7bDataTable
660         }
661          Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
662          $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
663     }
664      $replaceButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
665     $createChainButton.Enabled = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
666     $cleanupButton.Enabled = ($keystoreDataGridView.DataSource -ne $null)
667 })
668
669
670 $keystoreBrowseButton.Add_Click({
671     $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
672     $OpenFileDialog.Filter = "Keystore files (*.p12;*.pfx)|*.p12;*.pfx"
673     if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
674         $keystoreTextBox.Text = $OpenFileDialog.FileName
675     }
676 })
677
678
679
680 $replaceButton.Add_Click({
681     $selectedKeystoreIndex = $keystoreDataGridView.SelectedRows[0].Index
682     $selectedP7BIndex = $p7bDataGridView.SelectedRows[0].Index
683     $selectedKeystoreCert = $keystoreCertificates[$selectedKeystoreIndex]
684     $selectedP7BCert = $p7bCertificates[$selectedP7BIndex]
685
686     if ($selectedKeystoreCert -and $selectedP7BCert) {
687         $securePassword = Get-KeystorePassword
688
689         if ($securePassword) {
690             $replaceResult = Set-KeystoreCertificate -KeystorePath $keystoreTextBox.Text -KeystorePassword $securePassword -OldCertificate $selectedKeystoreCert -NewCertificate $selectedP7BCert
691              $securePassword.Dispose()
692             if($replaceResult){
693                 $refreshSecurePassword = Get-KeystorePassword
694                 if($refreshSecurePassword)
695                 {
696                     $updatedKeystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $refreshSecurePassword
697                     $refreshSecurePassword.Dispose()
698                     if ($updatedKeystoreCerts) {
699                         $keystoreCertificates.Clear()
700                          $keystoreDataTable = New-Object System.Data.DataTable
701                         $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
702                         $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
703                         $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
704                         $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
705                         $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
706                         $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
707                          $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null
708                         foreach ($cert in $updatedKeystoreCerts) {
709                             $row = $keystoreDataTable.NewRow()
710                             $row.Subject = $cert.Subject
711                             $row.Issuer = $cert.Issuer
712                             $row.NotBefore = $cert.NotBefore
713                             $row.NotAfter = $cert.NotAfter
714                             $row.Thumbprint = $cert.Thumbprint
715                             $row.SerialNumber = $cert.SerialNumber
716                             $row.SKI = Get-CertificateSKI $cert
717                             $keystoreDataTable.Rows.Add($row)
718                             $keystoreCertificates.Add($cert) | Out-Null
719                         }
720                         $keystoreDataGridView.DataSource = $keystoreDataTable
721                         Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
722                         $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
723                     }
724                 }
725
726             }
727         }
728     }
729     else
730     {
731         [System.Windows.Forms.MessageBox]::Show("Please select one certificate from Keystore and one from P7B to replace.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
732     }
733      #Keep enabled status.
734 })
735
736 $createChainButton.Add_Click({
737     $selectedKeystoreIndex = $keystoreDataGridView.SelectedRows[0].Index
738     $selectedKeystoreCert = $keystoreCertificates[$selectedKeystoreIndex]
739     $p7bCerts = $p7bDataGridView.DataSource
740
741     if($selectedKeystoreCert -and $p7bCerts -is [System.Data.DataTable])
742     {
743         $intermediateCerts = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
744         foreach($cert in $p7bCertificates)
745         {
746             $intermediateCerts.Add($cert)
747         }
748
749         $securePassword = Get-KeystorePassword
750         if($securePassword)
751         {
752             Build-CertificateChain -LeafCertificate $selectedKeystoreCert -IntermediateCertificates $intermediateCerts -KeystorePassword $securePassword
753              $securePassword.Dispose()
754         }
755     }
756      else
757     {
758         Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
759     }
760      #Keep enabled status.
761
762 })
763
764 $cleanupButton.Add_Click({
765     $securePassword = Get-KeystorePassword
766     if ($securePassword) {
767        $result = Cleanup-Keystore -KeystorePath $keystoreTextBox.Text -KeystorePassword $securePassword -KeystoreCertificates $keystoreCertificates -P7BCertificates $p7bCertificates
768        $securePassword.Dispose()
769
770         if($result){
771             $refreshSecurePassword = Get-KeystorePassword
772                 if($refreshSecurePassword)
773                 {
774                     $updatedKeystoreCerts = Get-KeystoreCertificates -KeystorePath $keystoreTextBox.Text -Password $refreshSecurePassword
775                     $refreshSecurePassword.Dispose()
776                     if ($updatedKeystoreCerts) {
777                         $keystoreCertificates.Clear()
778                          $keystoreDataTable = New-Object System.Data.DataTable
779                         $keystoreDataTable.Columns.Add("Subject", [string]) | Out-Null
780                         $keystoreDataTable.Columns.Add("Issuer", [string]) | Out-Null
781                         $keystoreDataTable.Columns.Add("NotBefore", [datetime]) | Out-Null
782                         $keystoreDataTable.Columns.Add("NotAfter", [datetime]) | Out-Null
783                         $keystoreDataTable.Columns.Add("Thumbprint", [string]) | Out-Null
784                         $keystoreDataTable.Columns.Add("SerialNumber", [string]) | Out-Null
785                          $keystoreDataTable.Columns.Add("SKI", [string]) | Out-Null
786                         foreach ($cert in $updatedKeystoreCerts) {
787                             $row = $keystoreDataTable.NewRow()
788                             $row.Subject = $cert.Subject
789                             $row.Issuer = $cert.Issuer
790                             $row.NotBefore = $cert.NotBefore
791                             $row.NotAfter = $cert.NotAfter
792                             $row.Thumbprint = $cert.Thumbprint
793                             $row.SerialNumber = $cert.SerialNumber
794                             $row.SKI = Get-CertificateSKI $cert
795                             $keystoreDataTable.Rows.Add($row)
796                             $keystoreCertificates.Add($cert) | Out-Null
797                         }
798                         $keystoreDataGridView.DataSource = $keystoreDataTable
799                         Compare-Certificates -KeystoreDataGridView $keystoreDataGridView -P7bDataGridView $p7bDataGridView
800                         $infoTextBox.Visible = ($keystoreDataGridView.DataSource -ne $null) -and ($p7bDataGridView.DataSource -ne $null)
801                     }
802                 }
803         }
804     }
805      #Keep enabled status.
806 })
807
808
809 $keystoreDataGridView.add_SelectionChanged({
810   #Keep Enabled Status.
811 })
812
813 $p7bDataGridView.add_SelectionChanged({
814    #Keep Enabled Status.
815 })
816
817 # --- Add Controls to Form ---
818
819 $form.Controls.Add($keystoreLabel)
820 $form.Controls.Add($keystoreTextBox)
821 $form.Controls.Add($keystoreBrowseButton)
822 $form.Controls.Add($keystoreOpenButton)
823 $form.Controls.Add($keystoreDataGridView)
824 $form.Controls.Add($p7bLabel)
825 $form.Controls.Add($p7bTextBox)
826 $form.Controls.Add($p7bBrowseButton)
827 $form.Controls.Add($p7bDataGridView)
828 $form.Controls.Add($replaceButton)
829 $form.Controls.Add($createChainButton)
830 $form.Controls.Add($cleanupButton)
831 $form.Controls.Add($infoTextBox)
832
833 # --- Show the Form ---
834 $form.ShowDialog()
