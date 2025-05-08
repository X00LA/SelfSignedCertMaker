# Beschreibung: Skript zur Erstellung eines selbstsignierten Zertifikats mit OpenSSL und Export im PEM-Format
# Autor: Markus Petautschnig
# Datum: 2025-05-08
# Version: 1.0
# Lizenz: MIT

# Beschreibung: This script creates a self-signed certificate with OpenSSL and exports it in PEM format.
# It checks whether OpenSSL is installed, whether the script is running with administrator privileges, and loads the configuration from an INI file.
# It creates the certificate, exports it in various formats, and displays the certificate details.

# Überprüfe, ob OpenSSL installiert ist
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Host "OpenSSL ist nicht installiert. Bitte installieren Sie OpenSSL und versuchen Sie es erneut." -ForegroundColor Red
    Write-Host "`nDrücken Sie eine beliebige Taste zum Beenden..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Fenster nach 5 Sekunden schließen
    Write-Host "`nDas Fenster wird in 5 Sekunden geschlossen..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}
else {
    Write-Host "OpenSSL ist installiert." -ForegroundColor Green
}

# Prüfe auf Admin-Rechte
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Dieses Skript benötigt Administrator-Rechte. Bitte als Administrator ausführen." -ForegroundColor Red
    Write-Host "Soll das Skript als Administrator ausgeführt werden? (J/N)" -ForegroundColor DarkYellow
    $response = Read-Host
    if ($response -eq "J" -or $response -eq "j") {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit 0
    }
    else {
        Write-Host "Das Skript wird ohne Administrator-Rechte beendet." -ForegroundColor Yellow
    }
    Write-Host "`nDrücken Sie eine beliebige Taste zum Beenden..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Fenster nach 5 Sekunden schließen
    Write-Host "`nDas Fenster wird in 5 Sekunden geschlossen..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}
else {
    Write-Host "Administrator-Rechte bestätigt." -ForegroundColor Green
}

# Konfiguration aus INI-Datei laden
$configFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.config.ini"
if ($configFiles.Count -eq 0) {
    Write-Host "Keine Konfigurationsdateien (*.config.ini) gefunden in: $PSScriptRoot" -ForegroundColor Red
    exit 1
}

if ($configFiles.Count -eq 1) {
    $configPath = $configFiles[0].FullName
}
else {
    Write-Host "Verfügbare Konfigurationen:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $configFiles.Count; $i++) {
        Write-Host "[$i] $($configFiles[$i].Name)" -ForegroundColor DarkCyan
    }
    
    do {
        $selection = Read-Host "`nWählen Sie eine Konfiguration (0-$($configFiles.Count - 1))"
    } while ($selection -notmatch '^\d+$' -or [int]$selection -lt 0 -or [int]$selection -ge $configFiles.Count)
    
    $configPath = $configFiles[[int]$selection].FullName
}

Write-Host "Verwende Konfiguration: $($configFiles[[int]$selection].Name)" -ForegroundColor Green

$config = @{}
Get-Content $configPath | ForEach-Object {
    if ($_ -match '^\[.*\]$') {
        $section = $_ -replace '[\[\]]', ''
    }
    elseif ($_ -match '=') {
        $name, $value = $_ -split '=', 2
        $config["$section.$name"] = $value.Trim()
    }
}

# Konfigurationswerte zuweisen
$certname = $config['Certificate.Name']
$certformat = $config['Certificate.Format']
$certoutformat = $config['Certificate.OutputFormat']
$mypwd = ConvertTo-SecureString -String $config['Certificate.Password'] -Force -AsPlainText
$certpath = $config['Certificate.Path']

# Prüfe und erstelle das Zertifikatsverzeichnis
if (-not (Test-Path $certpath)) {
    New-Item -ItemType Directory -Path $certpath -Force | Out-Null
}

if (Test-Path "$certpath\$certname.$certformat") {
    Write-Host "Zertifikatsdatei existiert bereits. Lösche alte Datei..." -ForegroundColor DarkYellow
    Remove-Item "$certpath\$certname.$certformat" -Force
}

# Prüfe und entferne existierendes Zertifikat im Store
$existingCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -eq "CN=$certname" }
if ($existingCert) {
    Write-Host "Zertifikat existiert im Store. Entferne altes Zertifikat..." -ForegroundColor DarkYellow
    Remove-Item -Path $existingCert.PSPath -Force
}

# Erstelle neues selbstsigniertes Zertifikat mit korrektem Store-Pfad
$cert = New-SelfSignedCertificate `
    -Subject "CN=$certname" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 4096 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

# Exportiere das Zertifikat im gewünschten Format
if ($certformat -eq "pfx") {
    Export-PfxCertificate -Cert $cert -FilePath "$certpath\$certname.$certformat" -Password $mypwd -Force
}
elseif ($certformat -eq "cer") {
    Export-Certificate -Cert $cert -FilePath "$certpath\$certname.$certformat" -Type CERT -Force
}
else {
    Write-Host "Ungültiges Format. Bitte 'pfx' oder 'cer' verwenden."   -ForegroundColor Red
    Write-Host "Das Skript wird beendet." -ForegroundColor Red
    Write-Host "`nDrücken Sie eine beliebige Taste zum Beenden..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Fenster nach 5 Sekunden schließen
    Write-Host "`nDas Fenster wird in 5 Sekunden geschlossen..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}

# Konvertiere zu PEM format
if ($certoutformat -eq "pem") {
    # Exportiere zunächst als PFX mit privatem Schlüssel
    $tempPfx = "$certpath\temp.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $tempPfx -Password $mypwd -Force

    # Konvertiere SecureString zu Klartext für OpenSSL
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($mypwd)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    # Extrahiere privaten Schlüssel
    $privateKey = "$certpath\privkey.pem"
    $null = & openssl pkcs12 -in $tempPfx -nocerts -out $privateKey -passin pass:$plainPassword -passout pass:$plainPassword

    # Extrahiere Zertifikat
    if (Test-Path "$certpath\$certname.$certoutformat") {
        Remove-Item "$certpath\$certname.$certoutformat" -Force
    }
    certutil.exe -encode "$certpath\$certname.$certformat" "$certpath\$certname.$certoutformat"
    
    # Lösche temporäre Dateien
    if (Test-Path $tempPfx) {
        Remove-Item $tempPfx -Force
    }
    if (Test-Path "$certpath\$certname.$certformat") {
        Remove-Item "$certpath\$certname.$certformat" -Force
    }

    # Säubere den Speicher
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Host "Private Key und Zertifikat wurden im PEM-Format exportiert:" -ForegroundColor Green
    Write-Host "Zertifikat: $certpath\$certname.$certoutformat" -ForegroundColor DarkMagenta
    Write-Host "Private Key: $privateKey" -ForegroundColor DarkMagenta
}

# Erstelle SSL Info Datei
$sslInfoPath = "$certpath\SSLInfo.txt"
$sslInfo = @"
Cert Path: $certpath\$certname.$certoutformat
Privkey Path: $certpath\privkey.pem
SSL Expiration Date (mm/dd/yyyy): $($cert.NotAfter.ToString("MM/dd/yyyy"))
"@

Set-Content -Path $sslInfoPath -Value $sslInfo -Force
Write-Host "`nSSL-Informationen wurden in SSLInfo.txt gespeichert:" -ForegroundColor Green
Write-Host $sslInfoPath -ForegroundColor DarkMagenta

# Zeige Zertifikatsdetails
$cert | Format-List -Property Subject, Thumbprint, NotBefore, NotAfter, FriendlyName

Write-Host "`nZertifikat wurde erfolgreich erstellt:"   -ForegroundColor Green
Write-Host "Speicherort: $certpath\$certname.$certoutformat"    -ForegroundColor DarkMagenta
Write-Host "Fingerabdruck: $($cert.Thumbprint)" -ForegroundColor DarkMagenta
Write-Host "Passwort: $mypwd" -ForegroundColor DarkMagenta
Write-Host "`nZertifikatdetails:" -ForegroundColor DarkMagenta
Write-Host "Ablaufdatum: $($cert.NotAfter)" -ForegroundColor DarkMagenta
Write-Host "`nBitte Passwort sicher aufbewahren!" -ForegroundColor DarkYellow

Write-Host "`nDrücken Sie eine beliebige Taste zum Beenden..." -ForegroundColor DarkYellow
[System.Console]::ReadKey() | Out-Null