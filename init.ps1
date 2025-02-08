# Initialization script for XSS Scanner

Write-Host "XSS Scanner - First Time Setup" -ForegroundColor Green
Write-Host "================================`n" -ForegroundColor Green

# Check if binaries exist
if (-Not (Test-Path "bin/xss-scanner.exe")) {
    Write-Host "XSS Scanner not found. Running installation script..." -ForegroundColor Yellow
    .\install.ps1
    if (-Not (Test-Path "bin/xss-scanner.exe")) {
        Write-Error "Installation failed. Please try running install.ps1 manually."
        Exit 1
    }
}

# Start test server
$testServer = Start-Process -FilePath "bin/test-server.exe" -PassThru -WindowStyle Hidden
Write-Host "Started test server on http://localhost:8080" -ForegroundColor Green

try {
    # Wait for server to start
    Start-Sleep -Seconds 2
    
    Write-Host "`nStarting example scan..." -ForegroundColor Yellow
    Write-Host "This will demonstrate scanning a test page with known XSS vulnerabilities.`n" -ForegroundColor Yellow
    
    # Run scanner with pre-configured options for the test server
    $scannerProcess = Start-Process -FilePath "bin/xss-scanner.exe" -NoNewWindow -Wait -PassThru
    
    if ($scannerProcess.ExitCode -ne 0) {
        Write-Error "Scanner encountered an error. Please check the output above."
    }
    
    Write-Host "`nExample scan complete!" -ForegroundColor Green
    Write-Host "You can now use 'xss-scanner.exe' to scan other targets." -ForegroundColor Green
    Write-Host "`nTips:" -ForegroundColor Cyan
    Write-Host "- Use verbose mode for detailed output" -ForegroundColor Cyan
    Write-Host "- Adjust crawling depth based on site size" -ForegroundColor Cyan
    Write-Host "- Add custom patterns for specific vulnerabilities" -ForegroundColor Cyan
    Write-Host "- Use custom headers for authenticated scans" -ForegroundColor Cyan
    
} finally {
    # Cleanup
    if ($testServer -and -not $testServer.HasExited) {
        Stop-Process -Id $testServer.Id -Force
        Write-Host "`nStopped test server" -ForegroundColor Yellow
    }
}

Write-Host "`nSetup complete! Happy scanning!" -ForegroundColor Green
