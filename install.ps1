# Installation script for XSS Scanner

# Ensure we're running with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator"
    Exit 1
}

Write-Host "Starting XSS Scanner installation..." -ForegroundColor Green

# Check if Go is installed
try {
    $goVersion = go version
    Write-Host "Found Go installation: $goVersion" -ForegroundColor Green
} catch {
    Write-Error "Go is not installed. Please install Go from https://golang.org/dl/"
    Exit 1
}

# Create bin directory if it doesn't exist
if (-Not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin"
    Write-Host "Created bin directory" -ForegroundColor Green
}

# Build the scanner
Write-Host "Building XSS Scanner..." -ForegroundColor Yellow
try {
    go build -o bin/xss-scanner.exe cmd/xss-scanner/main.go
    Write-Host "Successfully built XSS Scanner" -ForegroundColor Green
} catch {
    Write-Error "Failed to build XSS Scanner: $_"
    Exit 1
}

# Build the test server
Write-Host "Building test server..." -ForegroundColor Yellow
try {
    go build -o bin/test-server.exe cmd/test-server/main.go
    Write-Host "Successfully built test server" -ForegroundColor Green
} catch {
    Write-Error "Failed to build test server: $_"
    Exit 1
}

# Add to PATH (optional)
$installPath = Join-Path $PWD.Path "bin"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")

if (-Not ($userPath -like "*$installPath*")) {
    $response = Read-Host "Would you like to add XSS Scanner to your PATH? (y/n)"
    if ($response -eq 'y') {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$installPath", "User")
        Write-Host "Added XSS Scanner to PATH" -ForegroundColor Green
        Write-Host "Please restart your terminal for the PATH changes to take effect" -ForegroundColor Yellow
    }
}

Write-Host "`nInstallation Complete!" -ForegroundColor Green
Write-Host "You can now run the scanner using: xss-scanner.exe" -ForegroundColor Cyan
Write-Host "For testing, you can run: test-server.exe" -ForegroundColor Cyan
Write-Host "`nRun 'xss-scanner.exe' for interactive mode" -ForegroundColor Cyan
