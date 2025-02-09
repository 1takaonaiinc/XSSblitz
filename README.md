# XSS Scanner

A modern, microservices-based Cross-Site Scripting (XSS) vulnerability scanner with machine learning capabilities.

## Architecture

The scanner is built using a microservices architecture with the following components:

- **Scanner Service**: Core scanning engine for crawling and testing web pages
- **Detection Service**: ML-based and pattern-based XSS detection
- **Payload Service**: Dynamic payload generation with WAF bypass capabilities
- **Report Service**: Interactive HTML and JSON report generation
- **Coordinator Service**: Orchestrates all services and manages scanning workflow

## Features

- 🔍 Smart crawling and scanning of web applications
- 🧠 Machine Learning based XSS detection
- 🛡️ WAF bypass techniques
- 📊 Interactive HTML reports
- 🚀 Concurrent scanning
- 💾 Result caching
- 🎯 Context-aware payload generation
- 📋 Multiple output formats (HTML, JSON)

## Prerequisites

- Go 1.21 or higher
- Make

## Installation

1. Clone the repository:
```bash
git clone https://github.com/1takaonaiinc/xss-scanner.git
cd xss-scanner
```

2. Install dependencies:
```bash
make deps
```

3. Build the scanner:
```bash
make build
```

4. (Optional) Install globally:
```bash
make install
```

## Usage

Basic scan of a URL:
```bash
./bin/xss-scanner -url https://example.com
```

Advanced options:
```bash
./bin/xss-scanner -url https://example.com \
  -context html \
  -workers 10 \
  -timeout 60s \
  -model models/default.json \
  -report-dir reports \
  -cache=true \
  -cache-ttl 24h
```

### Command Line Options

- `-url`: Target URL to scan (required)
- `-context`: Context for payload generation (html, attr, js, url)
- `-workers`: Number of concurrent workers (default: 5)
- `-timeout`: Scan timeout duration (default: 30s)
- `-model`: Path to ML model file
- `-report-dir`: Directory for scan reports (default: reports)
- `-cache`: Enable result caching (default: true)
- `-cache-ttl`: Cache TTL duration (default: 24h)

## Development

### Project Structure
```
xss-scanner/
├── cmd/
│   └── scan/             # CLI application
├── services/
│   ├── scanner/          # Scanner service
│   ├── detector/         # Detection service
│   ├── payload/          # Payload generation service
│   ├── reporter/         # Report generation service
│   └── coordinator/      # Service orchestration
├── models/               # ML models
└── reports/              # Generated reports
```

### Make Commands

- `make build`: Build all services and CLI
- `make test`: Run tests
- `make clean`: Clean build files
- `make run`: Build and run scanner
- `make install`: Install scanner to GOPATH
- `make deps`: Download dependencies
- `make tidy`: Tidy go.mod files
- `make verify`: Verify dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

Please report security issues to [security@example.com](mailto:security@example.com).

## Acknowledgments

- Thanks to all contributors
- Inspired by modern web security tools and best practices
