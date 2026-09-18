Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting CipherGuard SOC Defensive Operations Workbench" -ForegroundColor Emerald
Write-Host "  8 Suites | 80 Tools | 5-Layer Threat Breakdown" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

# Start FastAPI backend in a background process
Write-Host "[1/2] Launching FastAPI Backend on http://127.0.0.1:8000 ..." -ForegroundColor Yellow
$backendProcess = Start-Process -FilePath "py" -ArgumentList "-3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -WorkingDirectory "$PSScriptRoot\backend" -PassThru

Start-Sleep -Seconds 2

# Start React + Vite frontend
Write-Host "[2/2] Launching React Vite Frontend on http://localhost:5173 ..." -ForegroundColor Yellow
Start-Process -FilePath "npm" -ArgumentList "run dev" -WorkingDirectory "$PSScriptRoot\frontend"

Write-Host "`n>>> CipherGuard is LIVE!" -ForegroundColor Green
Write-Host "  Frontend Workbench: http://localhost:5173" -ForegroundColor Cyan
Write-Host "  FastAPI Swagger UI: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "  Audit Ledger DB:    backend/data/cyber_suite.db`n" -ForegroundColor DarkGray
