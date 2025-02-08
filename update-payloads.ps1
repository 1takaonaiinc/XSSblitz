# Script to update XSS payloads from PortSwigger cheat sheet
# Can be scheduled to run periodically using Windows Task Scheduler

param(
    [switch]$Force,
    [int]$MinDaysBetweenUpdates = 7
)

$ErrorActionPreference = "Stop"

Write-Host "XSS Scanner - Payload Update Script" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if running from correct directory
if (-not (Test-Path "bin/update-payloads.exe")) {
    Write-Error "Please run this script from the xss-scanner root directory"
    Exit 1
}

# Check last update time
$lastUpdateFile = "models/last_update.txt"
$shouldUpdate = $Force

if (-not $shouldUpdate) {
    if (Test-Path $lastUpdateFile) {
        $lastUpdate = Get-Content $lastUpdateFile | Get-Date
        $daysSinceUpdate = ((Get-Date) - $lastUpdate).Days
        
        Write-Host "Last payload update was $daysSinceUpdate days ago"
        
        if ($daysSinceUpdate -ge $MinDaysBetweenUpdates) {
            $shouldUpdate = $true
        } else {
            Write-Host "Skipping update as it's been less than $MinDaysBetweenUpdates days"
            Exit 0
        }
    } else {
        $shouldUpdate = $true
    }
}

if ($shouldUpdate) {
    Write-Host "`nUpdating XSS payloads..." -ForegroundColor Yellow
    
    # Backup current model
    $backupPath = "models/default.json.bak"
    Copy-Item "models/default.json" $backupPath -Force
    Write-Host "Backed up current model to $backupPath" -ForegroundColor Green
    
    try {
        # Run payload updater
        & "./bin/update-payloads.exe"
        if ($LASTEXITCODE -ne 0) {
            throw "Payload update failed with exit code $LASTEXITCODE"
        }
        
        # Update timestamp
        Get-Date -Format "yyyy-MM-dd HH:mm:ss" | Set-Content $lastUpdateFile
        Write-Host "`nPayload update completed successfully!" -ForegroundColor Green
        
    } catch {
        Write-Error "Error during update: $_"
        Write-Host "Restoring backup..." -ForegroundColor Yellow
        Copy-Item $backupPath "models/default.json" -Force
        Exit 1
    }
} else {
    Write-Host "No update needed at this time"
}
