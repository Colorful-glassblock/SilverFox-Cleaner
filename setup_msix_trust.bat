@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>nul || (echo [ERR] run from an elevated prompt & exit /b 1)

if not exist "SFCleaner_TemporaryKey.pfx" (
    echo [ERR] run build_all.bat first
    exit /b 1
)

echo Importing test cert to LocalMachine TrustedPeople ...
powershell -NoProfile -Command "Import-PfxCertificate -FilePath 'SFCleaner_TemporaryKey.pfx' -CertStoreLocation Cert:\LocalMachine\TrustedPeople -Password (ConvertTo-SecureString -String 'sf-cleaner-test' -AsPlainText -Force)"
if errorlevel 1 goto :err

reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowAllTrustedApps >nul 2>nul || reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowAllTrustedApps /t REG_DWORD /d 1

echo OK - sideload enabled. Double-click dist\*.msix to install.
exit /b 0

:err
echo [FAILED] cert import error
exit /b 1
