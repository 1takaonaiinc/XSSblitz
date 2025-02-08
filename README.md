# XSSBlitz - Advanced XSS Scanner

XSSBlitz is a powerful Cross-Site Scripting (XSS) vulnerability scanner with machine learning capabilities, designed to help security professionals and developers identify potential XSS vulnerabilities in web applications.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Advanced Configuration](#advanced-configuration)
- [Machine Learning Integration](#machine-learning-integration)
- [Troubleshooting](#troubleshooting)

## Features

### Core Capabilities
- ML-powered XSS detection with customizable threshold
- Intelligent crawling with adjustable depth
- Automatic keyword extraction from web content
- Concurrent scanning for improved performance
- Custom header support for authenticated scanning
- Comprehensive reporting with severity levels

### Key Benefits
- High accuracy with minimal false positives
- Easy-to-use interactive interface
- Flexible configuration options
- Built-in machine learning model
- Regular payload updates

## Installation

### System Requirements
- Windows 10 or later
- Go 1.21 or later
- PowerShell 5.0 or later

### Quick Install
```powershell
# Clone the repository
git clone https://github.com/1takaonaiinc/xss-scanner
cd xss-scanner

# Run the installation script
.\install.ps1
```

### Manual Installation
```powershell
# Build from source
go build -o bin/xss-scanner.exe cmd/xss-scanner/main.go
```

## Usage

### Basic Scan
```powershell
.\bin\xss-scanner.exe
```
Follow the interactive prompts to configure your scan:

1. Enter target URL (required)
2. Specify custom XSS patterns (optional)
3. Configure ML model settings
4. Set scanning parameters
5. Enable/disable verbose output

### Configuration Options

#### Target URL
- Must start with `http://` or `https://`
- Example: `https://example.com`

#### Custom XSS Patterns
- Comma-separated list of patterns
- Leave empty to use default patterns
- Example: `<script>alert(1)</script>,javascript:alert(1)`

#### ML Model Settings
- Model file path (default: models/default.json)
- Detection threshold (0.0-1.0, default: 0.7)
- Higher threshold = fewer false positives

#### Scan Parameters
- URLs to exclude (comma-separated)
- Parameters to check (comma-separated)
- Timeout in seconds (default: 30)
- Concurrent scans (default: 5)
- Crawling depth (default: 2)

#### Custom Headers
Format: `key1:value1,key2:value2`
Example: `Authorization:Bearer token,X-Custom:value`

## Advanced Configuration

### Updating Payloads
```powershell
# Update XSS payload database
.\update-payloads.ps1
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install XSSBlitz
        run: .\install.ps1
      - name: Run Scan
        run: .\bin\xss-scanner.exe --ci --url ${{ secrets.TARGET_URL }}
```

### Custom ML Model Training
1. Prepare training data in CSV format
2. Use the provided scripts in the `models` directory
3. Replace `default.json` with your trained model

## Machine Learning Integration

### Model Overview
- Based on natural language processing
- Features extracted from HTML context
- Trained on real-world XSS payloads
- Regular updates via payload database

### Threshold Configuration
- 0.7: Balanced detection (default)
- 0.8: Lower false positives
- 0.6: Higher detection rate
- Adjust based on your security requirements

## Troubleshooting

### Common Issues

#### Scanner fails to start
```
Error: Cannot load ML model
Solution: Verify models/default.json exists and is valid
```

#### Connection errors
```
Error: Connection timeout
Solution: Check network connectivity and increase timeout value
```

#### False positives
```
Issue: Too many false positive results
Solution: Increase ML detection threshold (e.g., 0.8 or higher)
```

### Best Practices
1. Start with default configuration
2. Enable verbose mode for detailed output
3. Adjust thresholds based on results
4. Use custom headers for authenticated scans
5. Regularly update payloads database

## Support

- GitHub Issues: Report bugs and feature requests
- Documentation: Refer to inline code comments
- Updates: Check release notes for new features

## License
MIT License - See LICENSE file for details
