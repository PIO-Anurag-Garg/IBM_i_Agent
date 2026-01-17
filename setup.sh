#!/usr/bin/env bash
# IBM i Performance Agent - Unix Setup Script
# Usage: chmod +x setup.sh && ./setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} IBM i Performance Agent - Setup${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Step 1: Check Python version
echo -e "${YELLOW}[1/5] Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo -e "  ${RED}ERROR: Python not found. Please install Python 3.8+${NC}"
    echo "  macOS: brew install python3"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-venv"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 8 ]); then
    echo -e "  ${RED}ERROR: Python 3.8+ required. Found: Python $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "  Found: Python $PYTHON_VERSION ${GREEN}[OK]${NC}"

# Step 2: Create virtual environment
echo -e "${YELLOW}[2/5] Creating virtual environment...${NC}"
if [ -d ".venv" ]; then
    echo -e "  ${GRAY}Virtual environment already exists, skipping.${NC}"
else
    $PYTHON_CMD -m venv .venv
    echo -e "  Created .venv directory ${GREEN}[OK]${NC}"
fi

# Step 3: Activate and install dependencies
echo -e "${YELLOW}[3/5] Installing dependencies...${NC}"
source .venv/bin/activate
pip install --upgrade pip --quiet 2>/dev/null
pip install -r requirements.txt --quiet 2>/dev/null
echo -e "  Installed: python-dotenv, mapepire-python, pep249, agno, openai ${GREEN}[OK]${NC}"

# Step 4: Create .env if missing
echo -e "${YELLOW}[4/5] Checking configuration...${NC}"
if [ -f ".env" ]; then
    echo -e "  ${GRAY}.env file already exists, skipping.${NC}"
else
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "  Created .env from .env.example ${GREEN}[OK]${NC}"
    else
        echo -e "  ${YELLOW}WARNING: .env.example not found, skipping .env creation${NC}"
    fi
fi

# Step 5: Done - show next steps
echo -e "${GREEN}[5/5] Setup complete!${NC}"
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN} Next Steps${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "1. Edit .env with your credentials:"
echo -e "   ${CYAN}nano .env${NC}  (or use your preferred editor)"
echo ""
echo -e "   ${GRAY}Required settings:${NC}"
echo -e "   ${GRAY}- IBMI_HOST=your-ibmi-hostname${NC}"
echo -e "   ${GRAY}- IBMI_USER=your-username${NC}"
echo -e "   ${GRAY}- IBMI_PASSWORD=your-password${NC}"
echo -e "   ${GRAY}- OPENROUTER_API_KEY=sk-or-...${NC}"
echo ""
echo -e "2. Activate the virtual environment:"
echo -e "   ${CYAN}source .venv/bin/activate${NC}"
echo ""
echo -e "3. Test connection (optional):"
echo -e "   ${CYAN}python test_mapepire.py${NC}"
echo ""
echo -e "4. Run the agent:"
echo -e "   ${CYAN}python ibmi_agent.py${NC}"
echo ""
echo -e "${YELLOW}Get an OpenRouter API key at: https://openrouter.ai/settings/keys${NC}"
echo ""
