# Description: Script for creating a self-signed certificate with OpenSSL and export in PEM format
# Author: Markus Petautschnig
# Date: 2025-05-08
# Version: 1.0
# License: MIT

# Description: This script creates a self-signed certificate with OpenSSL and exports it in PEM format.
# It checks whether OpenSSL is installed, whether the script is running with administrator privileges, and loads the configuration from an INI file.
# It creates the certificate, exports it in various formats, and displays the certificate details.

# Check if OpenSSL is installed
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Host "OpenSSL is not installed. Please install OpenSSL and try again." -ForegroundColor Red
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Close window after 5 seconds
    Write-Host "`nWindow will close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}
else {
    Write-Host "OpenSSL is installed." -ForegroundColor Green
}

# Check for admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires administrator rights. Please run as administrator." -ForegroundColor Red
    Write-Host "Do you want to run the script as administrator? (Y/N)" -ForegroundColor DarkYellow
    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "y") {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit 0
    }
    else {
        Write-Host "Script will exit without administrator rights." -ForegroundColor Yellow
    }
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Close window after 5 seconds
    Write-Host "`nWindow will close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}
else {
    Write-Host "Administrator rights confirmed." -ForegroundColor Green
}

# Load configuration from INI file
$configFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.config.ini"
if ($configFiles.Count -eq 0) {
    Write-Host "No configuration files (*.config.ini) found in: $PSScriptRoot" -ForegroundColor Red
    exit 1
}

if ($configFiles.Count -eq 1) {
    $configPath = $configFiles[0].FullName
}
else {
    Write-Host "Available configurations:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $configFiles.Count; $i++) {
        Write-Host "[$i] $($configFiles[$i].Name)" -ForegroundColor DarkCyan
    }
    
    do {
        $selection = Read-Host "`nSelect a configuration (0-$($configFiles.Count - 1))"
    } while ($selection -notmatch '^\d+$' -or [int]$selection -lt 0 -or [int]$selection -ge $configFiles.Count)
    
    $configPath = $configFiles[[int]$selection].FullName
}

Write-Host "Using configuration: $($configFiles[[int]$selection].Name)" -ForegroundColor Green

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

# Assign configuration values
$certname = $config['Certificate.Name']
$certformat = $config['Certificate.Format']
$certoutformat = $config['Certificate.OutputFormat']
$mypwd = ConvertTo-SecureString -String $config['Certificate.Password'] -Force -AsPlainText
$certpath = $config['Certificate.Path']

# Check and create certificate directory
if (-not (Test-Path $certpath)) {
    New-Item -ItemType Directory -Path $certpath -Force | Out-Null
}

if (Test-Path "$certpath\$certname.$certformat") {
    Write-Host "Certificate file already exists. Deleting old file..." -ForegroundColor DarkYellow
    Remove-Item "$certpath\$certname.$certformat" -Force
}

# Check and remove existing certificate in store
$existingCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -eq "CN=$certname" }
if ($existingCert) {
    Write-Host "Certificate exists in store. Removing old certificate..." -ForegroundColor DarkYellow
    Remove-Item -Path $existingCert.PSPath -Force
}

# Create new self-signed certificate with correct store path
$cert = New-SelfSignedCertificate `
    -Subject "CN=$certname" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 4096 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

# Export the certificate in the desired format
if ($certformat -eq "pfx") {
    Export-PfxCertificate -Cert $cert -FilePath "$certpath\$certname.$certformat" -Password $mypwd -Force
}
elseif ($certformat -eq "cer") {
    Export-Certificate -Cert $cert -FilePath "$certpath\$certname.$certformat" -Type CERT -Force
}
else {
    Write-Host "Invalid format. Please use 'pfx' or 'cer'." -ForegroundColor Red
    Write-Host "Script will exit." -ForegroundColor Red
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    [System.Console]::ReadKey() | Out-Null
    # Optional: Close window after 5 seconds
    Write-Host "`nWindow will close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}

# Convert to PEM format
if ($certoutformat -eq "pem") {
    # Export first as PFX with private key
    $tempPfx = "$certpath\temp.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $tempPfx -Password $mypwd -Force

    # Convert SecureString to plaintext for OpenSSL
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($mypwd)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    # Extract private key
    $privateKey = "$certpath\privkey.pem"
    $null = & openssl pkcs12 -in $tempPfx -nocerts -out $privateKey -passin pass:$plainPassword -passout pass:$plainPassword

    # Extract certificate
    if (Test-Path "$certpath\$certname.$certoutformat") {
        Remove-Item "$certpath\$certname.$certoutformat" -Force
    }
    certutil.exe -encode "$certpath\$certname.$certformat" "$certpath\$certname.$certoutformat"
    
    # Delete temporary files
    if (Test-Path $tempPfx) {
        Remove-Item $tempPfx -Force
    }
    if (Test-Path "$certpath\$certname.$certformat") {
        Remove-Item "$certpath\$certname.$certformat" -Force
    }

    # Clear memory
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Host "Private Key and Certificate were exported in PEM format:" -ForegroundColor Green
    Write-Host "Certificate: $certpath\$certname.$certoutformat" -ForegroundColor DarkMagenta
    Write-Host "Private Key: $privateKey" -ForegroundColor DarkMagenta
}

# Create SSL Info file
$sslInfoPath = "$certpath\SSLInfo.txt"
$sslInfo = @"
Cert Path: $certpath\$certname.$certoutformat
Privkey Path: $certpath\privkey.pem
SSL Expiration Date (mm/dd/yyyy): $($cert.NotAfter.ToString("MM/dd/yyyy"))
"@

Set-Content -Path $sslInfoPath -Value $sslInfo -Force
Write-Host "`nSSL information has been saved to SSLInfo.txt:" -ForegroundColor Green
Write-Host $sslInfoPath -ForegroundColor DarkMagenta

# Display certificate details
$cert | Format-List -Property Subject, Thumbprint, NotBefore, NotAfter, FriendlyName

Write-Host "`nCertificate was successfully created:" -ForegroundColor Green
Write-Host "Location: $certpath\$certname.$certoutformat" -ForegroundColor DarkMagenta
Write-Host "Fingerprint: $($cert.Thumbprint)" -ForegroundColor DarkMagenta
Write-Host "Password: $mypwd" -ForegroundColor DarkMagenta
Write-Host "`nCertificate details:" -ForegroundColor DarkMagenta
Write-Host "Expiration date: $($cert.NotAfter)" -ForegroundColor DarkMagenta
Write-Host "`nPlease store password securely!" -ForegroundColor DarkYellow

Write-Host "`nPress any key to exit..." -ForegroundColor DarkYellow
[System.Console]::ReadKey() | Out-Null