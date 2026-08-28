@echo off
setlocal
cd /d "%~dp0"

set OUT=%CD%\dist
set PUB=bin\x64\Release\net8.0-windows10.0.22621.0\win-x64\publish
if not exist "%OUT%" mkdir "%OUT%"

where dotnet >nul 2>nul || (echo [ERR] dotnet 8 SDK not found in PATH & exit /b 1)

echo ============================================================
echo  SilverFox Cleaner v5 - multi-target build
echo  [1] framework-dep  [2] self-contained  [3] MSIX
echo  NOTE: single-file removed - WinUI3 unsupported by MS
echo ============================================================

call :clean

echo.
echo --- [1/3] framework-dependent - needs .NET 8 Desktop + Windows App SDK Runtime ---
dotnet publish -c Release -p:Platform=x64 -p:WindowsPackageType=None -p:SelfContained=false -p:WindowsAppSDKSelfContained=false -p:PublishSingleFile=false || goto :err
call :grab framework-dependent || goto :err

call :clean
echo.
echo --- [2/3] self-contained - zero runtime deps on target ---
dotnet publish -c Release -p:Platform=x64 -p:WindowsPackageType=None -p:SelfContained=true -p:PublishSingleFile=false || goto :err
call :grab self-contained || goto :err

call :clean
echo.
echo --- [3/3] MSIX sideload package - manual makeappx + signtool route ---
call build_msix_manual.bat || goto :err

echo.
echo DONE. Output in %OUT%
echo   framework-dependent\SFCleaner.exe   - needs .NET 8 Desktop + WinAppSDK Runtime
echo   self-contained\SFCleaner.exe        - runs anywhere, x64 folder layout
echo   SFCleaner.msix                      - sideload after setup_msix_trust.bat
echo.
echo NOTE: 4th variant (single-file) removed - Microsoft confirms WinUI 3
echo       does not support PublishSingleFile (resources.pri lookup fails at
echo       startup). Use the self-contained folder or MSIX instead.
exit /b 0

:grab
rmdir /s /q "%OUT%\%~1" >nul 2>nul
robocopy "%PUB%" "%OUT%\%~1" /mir /njh /njs /ndl >nul
if errorlevel 8 (
    echo [ERR] robocopy failed collecting %~1
    exit /b 1
)
exit /b 0

:clean
rmdir /s /q "%CD%\bin" >nul 2>nul
rmdir /s /q "%CD%\obj" >nul 2>nul
rmdir /s /q "%CD%\msix-stage" >nul 2>nul
rmdir /s /q "%CD%\msix-layout-root" >nul 2>nul
exit /b 0

:makecert
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; try { $c = New-SelfSignedCertificate -Type Custom -Subject 'CN=SFCleaner Research' -KeyUsage DigitalSignature -FriendlyName 'SFCleaner test signing' -NotAfter (Get-Date).AddYears(3) -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}'); $p = ConvertTo-SecureString -String 'sf-cleaner-test' -Force -AsPlainText; Export-PfxCertificate -Cert $c -FilePath 'SFCleaner_TemporaryKey.pfx' -Password $p | Out-Null; Write-Host ('thumbprint: ' + $c.Thumbprint) } catch { Write-Host ('CERT ERROR: ' + $_.Exception.Message); exit 1 }"
exit /b %ERRORLEVEL%

:err
echo.
echo [BUILD FAILED]
exit /b 1