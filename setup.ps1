#!/usr/bin/env pwsh
# IBM i Performance Agent - Windows Setup Script
# Usage: .\setup.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " IBM i Performance Agent - Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python version
Write-Host "[1/5] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
            Write-Host "  ERROR: Python 3.8+ required. Found: $pythonVersion" -ForegroundColor Red
            Write-Host "  Download: https://www.python.org/downloads/" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "  Found: $pythonVersion [OK]" -ForegroundColor Green
    }
} catch {
    Write-Host "  ERROR: Python not found. Please install Python 3.8+" -ForegroundColor Red
    Write-Host "  Download: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Step 2: Create virtual environment
Write-Host "[2/5] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path ".venv") {
    Write-Host "  Virtual environment already exists, skipping." -ForegroundColor DarkGray
} else {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Created .venv directory [OK]" -ForegroundColor Green
}

# Step 3: Activate and install dependencies
Write-Host "[3/5] Installing dependencies..." -ForegroundColor Yellow
try {
    & .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip --quiet 2>&1 | Out-Null
    pip install -r requirements.txt --quiet 2>&1 | Out-Null
    Write-Host "  Installed: python-dotenv, mapepire-python, pep249, agno, openai [OK]" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Failed to install dependencies" -ForegroundColor Red
    Write-Host "  Try running: pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# Step 4: Create .env if missing
Write-Host "[4/5] Checking configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "  .env file already exists, skipping." -ForegroundColor DarkGray
} else {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "  Created .env from .env.example [OK]" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: .env.example not found, skipping .env creation" -ForegroundColor Yellow
    }
}

# Step 5: Done - show next steps
Write-Host "[5/5] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Next Steps" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Edit .env with your credentials:" -ForegroundColor White
Write-Host "   notepad .env" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Required settings:" -ForegroundColor DarkGray
Write-Host "   - IBMI_HOST=your-ibmi-hostname" -ForegroundColor DarkGray
Write-Host "   - IBMI_USER=your-username" -ForegroundColor DarkGray
Write-Host "   - IBMI_PASSWORD=your-password" -ForegroundColor DarkGray
Write-Host "   - OPENROUTER_API_KEY=sk-or-..." -ForegroundColor DarkGray
Write-Host ""
Write-Host "2. Activate the virtual environment:" -ForegroundColor White
Write-Host "   .\.venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Test connection (optional):" -ForegroundColor White
Write-Host "   python test_mapepire.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Run the agent:" -ForegroundColor White
Write-Host "   python ibmi_agent.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "Get an OpenRouter API key at: https://openrouter.ai/settings/keys" -ForegroundColor Yellow
Write-Host ""
