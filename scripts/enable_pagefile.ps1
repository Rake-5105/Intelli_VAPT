# =============================================================================
# IntelliVAPT — Enable Windows System-Managed Pagefile
# Solves: "The paging file is too small for this operation to complete"
# =============================================================================

Write-Host "Configuring Windows System-Managed Pagefile on C:..." -ForegroundColor Cyan

try {
    # 1. Enable Automatic Managed Pagefile via WMI
    Set-CimInstance -Query 'Select * from Win32_ComputerSystem' -Property @{AutomaticManagedPagefile = $true}
    Write-Host "[✓] Automatic Managed Pagefile enabled via WMI." -ForegroundColor Green
} catch {
    Write-Warning "WMI method: $_"
}

try {
    # 2. Registry fallback for system managed pagefile on C:
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value @('C:\pagefile.sys 0 0')
    Write-Host "[✓] Registry PagingFiles set to 'C:\pagefile.sys 0 0'." -ForegroundColor Green
} catch {
    Write-Warning "Registry method: $_"
}

Write-Host ""
Write-Host "Pagefile configuration complete!" -ForegroundColor Green
Write-Host "Note: A computer restart is recommended for Windows to allocate the new pagefile." -ForegroundColor Yellow
Start-Sleep -Seconds 5
