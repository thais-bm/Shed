# Script para iniciar automaticamente o Servidor Relé (8000), Cliente Local 1 (8001) e Cliente Local 2 (8002)
$root = $PSScriptRoot

Write-Host "Iniciando Servidor Rele na porta 8000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\server'; uv run uvicorn server:app --reload --host 127.0.0.1 --port 8000"

Start-Sleep -Seconds 2

Write-Host "Iniciando Instancia Local 1 na porta 8001..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\client\backend'; uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8001"

Write-Host "Iniciando Instancia Local 2 na porta 8002..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\client\backend'; uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8002"

Write-Host "Iniciando Frontend 1 na porta 5173 (API 8001)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:VITE_API_BASE_URL='http://127.0.0.1:8001'; cd '$root\client\frontend'; & '$root\client\frontend\node_modules\.bin\vite.cmd' --host 127.0.0.1 --port 5173"

Write-Host "Iniciando Frontend 2 na porta 5174 (API 8002)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:VITE_API_BASE_URL='http://127.0.0.1:8002'; cd '$root\client\frontend'; & '$root\client\frontend\node_modules\.bin\vite.cmd' --host 127.0.0.1 --port 5174"

Write-Host "`nTudo pronto! Acesse no navegador:" -ForegroundColor Magenta
Write-Host "  - Rele:       http://127.0.0.1:8000/docs"
Write-Host "  - Cliente 1:  http://127.0.0.1:8001/docs"
Write-Host "  - Cliente 2:  http://127.0.0.1:8002/docs"
Write-Host "  - Frontend 1:  http://127.0.0.1:5173 (API 8001)"
Write-Host "  - Frontend 2:  http://127.0.0.1:5174 (API 8002)"
