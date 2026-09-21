@echo off
echo [IntelliVAPT] Requesting Administrator privileges to configure Windows Pagefile...
powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0enable_pagefile.ps1\"'"
echo Done. If the Windows UAC prompt appeared, please click 'Yes'.
pause
