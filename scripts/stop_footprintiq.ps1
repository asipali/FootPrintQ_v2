<#
.SYNOPSIS
    Stops running FootprintIQ application server processes.
.DESCRIPTION
    Identifies and terminates Python processes running Uvicorn on port 8000.
.EXAMPLE
    .\scripts\stop_footprintiq.ps1
#>

param(
    [int]$Port = 8000
)

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " STOPPING FOOTPRINTIQ PLATFORM (PORT $Port)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Find processes listening on port
$Connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if (-not $Connections) {
    Write-Host "[*] No active connections found listening on port $Port." -ForegroundColor Green
    exit 0
}

$ProcessIds = $Connections | Select-Object -ExpandProperty OwningProcess -Unique

foreach ($PidNum in $ProcessIds) {
    if ($PidNum -le 4) { continue }
    try {
        $Proc = Get-Process -Id $PidNum -ErrorAction Stop
        Write-Host "[*] Stopping process $($Proc.ProcessName) (PID: $PidNum)..." -ForegroundColor Yellow
        Stop-Process -Id $PidNum -Force
        Write-Host "[+] Successfully stopped PID $PidNum." -ForegroundColor Green
    } catch {
        Write-Warning "[-] Could not stop PID ${PidNum}: $_"
    }
}

Write-Host "[+] FootprintIQ server stopped." -ForegroundColor Green

