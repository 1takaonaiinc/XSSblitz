#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Running XSS Scanner Test Plan..."

# Step 1: Run tests
echo -e "\n${GREEN}1. Running tests...${NC}"
make test
if [ $? -ne 0 ]; then
    echo -e "${RED}Tests failed!${NC}"
    exit 1
fi

# Step 2: Build project
echo -e "\n${GREEN}2. Building project...${NC}"
make build
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Step 3: Run sample scan
echo -e "\n${GREEN}3. Running sample scan...${NC}"
./bin/xss-scanner -url https://example.com -context html
if [ $? -ne 0 ]; then
    echo -e "${RED}Sample scan failed!${NC}"
    exit 1
fi

# Step 4: Check report generation
echo -e "\n${GREEN}4. Checking report generation...${NC}"
if [ ! -d "reports" ]; then
    echo -e "${RED}Reports directory not found!${NC}"
    exit 1
fi

echo -e "\n${GREEN}All tests completed successfully!${NC}"
echo "You can now commit and push to GitHub:"
echo "git add ."
echo "git commit -m \"Initial implementation of XSS scanner\""
echo "git push origin main"
