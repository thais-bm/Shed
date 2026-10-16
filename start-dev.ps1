# Script para iniciar automaticamente o Servidor Relé (8000), Cliente Local 1 (8001) e Cliente Local 2 (8002)
$root = $PSScriptRoot

Write-Host "Iniciando Servidor Rele na porta 8000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\server'; uv run uvicorn server:app --reload --host 127.0.0.1 --port 8000"

Start-Sleep -Seconds 2

Write-Host "Iniciando Instancia Local 1 na porta 8001..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\client\backend'; uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8001"

Write-Host "Iniciando Instancia Local 2 na porta 8002..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\client\backend'; uv run uvicorn backend.api:app --reload --host 127.0.0.1 --port 8002"

Write-Host "`nTudo pronto! Acesse no navegador:" -ForegroundColor Magenta
Write-Host "  - Rele:       http://127.0.0.1:8000/docs"
Write-Host "  - Cliente 1:  http://127.0.0.1:8001/docs"
Write-Host "  - Cliente 2:  http://127.0.0.1:8002/docs"
