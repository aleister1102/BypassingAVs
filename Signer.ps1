param(
    [Parameter(Mandatory=$true)]
    [System.Security.SecureString]$Password,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$BinaryPath
)

# Check if OpenSSL is installed
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Error "OpenSSL is not installed. Please install OpenSSL and try again."
    exit 1
}

# Check if signtool is available
if (-not (Get-Command signtool -ErrorAction SilentlyContinue)) {
    Write-Error "signtool is not found. Please ensure Windows SDK is installed and signtool is in your PATH."
    exit 1
}

# Convert SecureString to plain text (only used for command parameters)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Generate SSL certificate and key
Write-Host "Generating SSL certificate and key..."
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -subj "/CN=Test Certificate" -nodes

# Create PFX file
Write-Host "Creating PFX file..."
openssl pkcs12 -inkey key.pem -in cert.pem -export -out sign.pfx -passout "pass:$PlainPassword"

# Sign the executable
Write-Host "Signing executable..."
signtool sign /f sign.pfx /p $PlainPassword /t http://timestamp.digicert.com /fd sha256 $BinaryPath

# Clean up temporary files
Write-Host "Cleaning up temporary files..."
Remove-Item key.pem, cert.pem, sign.pfx -Force

Write-Host "Process completed successfully!"