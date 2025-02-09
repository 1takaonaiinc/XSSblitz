.PHONY: all build clean test install run

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=xss-scanner

# Services
SERVICES=services/scanner-service services/detection-service services/payload-service services/report-service services/coordinator

all: clean deps build

deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	@for service in $(SERVICES); do \
		echo "Installing dependencies for $$service..."; \
		cd $$service && $(GOMOD) download && cd ../..; \
	done

build:
	@echo "Building services..."
	@for service in $(SERVICES); do \
		echo "Building $$service..."; \
		cd $$service && $(GOBUILD) && cd ../..; \
	done
	@echo "Building scanner CLI..."
	cd cmd/scan && $(GOBUILD) -o ../../bin/$(BINARY_NAME)

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...
	@for service in $(SERVICES); do \
		echo "Testing $$service..."; \
		cd $$service && $(GOTEST) -v ./... && cd ../..; \
	done

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	@for service in $(SERVICES); do \
		echo "Cleaning $$service..."; \
		cd $$service && rm -f *.out && cd ../..; \
	done

run: build
	@echo "Running scanner..."
	./bin/$(BINARY_NAME)

install: build
	@echo "Installing scanner..."
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/

# Development helpers
tidy:
	@echo "Tidying modules..."
	$(GOMOD) tidy
	@for service in $(SERVICES); do \
		echo "Tidying $$service..."; \
		cd $$service && $(GOMOD) tidy && cd ../..; \
	done

verify:
	@echo "Verifying modules..."
	$(GOMOD) verify
	@for service in $(SERVICES); do \
		echo "Verifying $$service..."; \
		cd $$service && $(GOMOD) verify && cd ../..; \
	done

# Help command
help:
	@echo "Available commands:"
	@echo "  make build    - Build all services and CLI"
	@echo "  make test     - Run tests"
	@echo "  make clean    - Clean build files"
	@echo "  make run      - Build and run scanner"
	@echo "  make install  - Install scanner to GOPATH"
	@echo "  make deps     - Download dependencies"
	@echo "  make tidy     - Tidy go.mod files"
	@echo "  make verify   - Verify dependencies"
