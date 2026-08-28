@echo off
setlocal
cd /d "%~dp0"

where dotnet >nul 2>nul || (echo [ERR] dotnet not found & exit /b 1)

rem Windows SDK BuildTools 的 makeappx/signtool 位于 nuget 全局包缓存（路径可能被 NuGet.Config 重定向）
rem for /d 多级通配在含撇号路径上不可靠，改用 dir /s /b 递归解析
set BTBIN=
for /f "delims=" %%f in ('dir /b /s "%USERPROFILE%\.nuget\packages\microsoft.windows.sdk.buildtools\makeappx.exe" 2^>nul ^| findstr /l /c:"\x64\makeappx.exe"') do if not defined BTBIN set "BTBIN=%%~dpf"
if not defined BTBIN for /f "delims=" %%f in ('dir /b /s "%LOCALAPPDATA%\.nuget\packages\microsoft.windows.sdk.buildtools\makeappx.exe" 2^>nul ^| findstr /l /c:"\x64\makeappx.exe"') do if not defined BTBIN set "BTBIN=%%~dpf"
if not defined BTBIN for /f "delims=" %%f in ('where /r "C:\Program Files (x86)\Windows Kits" makeappx.exe 2^>nul ^| findstr /l /c:"\x64\makeappx.exe"') do if not defined BTBIN set "BTBIN=%%~dpf"
if not defined BTBIN (
    echo [ERR] makeappx.exe not found - install Windows SDK or run dotnet restore first
    exit /b 1
)
echo toolchain: %BTBIN%

echo [1/4] self-contained publish ...
rmdir /s /q "%CD%\obj" >nul 2>nul
rmdir /s /q "%CD%\bin" >nul 2>nul
dotnet publish -c Release -p:Platform=x64 -p:WindowsPackageType=None -p:SelfContained=true -p:PublishSingleFile=false || goto :err

echo [2/4] assemble package layout ...
set PUB=bin\x64\Release\net8.0-windows10.0.22621.0\win-x64\publish
set LAYOUT=%CD%\msix-layout-root
rmdir /s /q "%LAYOUT%" >nul 2>nul
mkdir "%LAYOUT%"
xcopy "%PUB%\*" "%LAYOUT%\" /e /i /y >nul || goto :err
copy /y "msix\Package.appxmanifest" "%LAYOUT%\AppxManifest.xml" >nul || goto :err
xcopy "%CD%\Assets\*" "%LAYOUT%\Assets\" /e /i /y >nul || goto :err

if exist "SFCleaner_TemporaryKey.pfx" goto :havecert
echo [3/4] generating self-signed test cert ...
call :makecert || goto :err
:havecert
if not exist "SFCleaner_TemporaryKey.pfx" goto :err

echo [4/4] makeappx + signtool ...
if not exist "%CD%\dist" mkdir "%CD%\dist"
"%BTBIN%\makeappx.exe" pack /o /d "%LAYOUT%" /p "%CD%\dist\SFCleaner.msix" || goto :err
"%BTBIN%\signtool.exe" sign /fd SHA256 /a /f "SFCleaner_TemporaryKey.pfx" /p sf-cleaner-test "%CD%\dist\SFCleaner.msix" || goto :err

echo.
echo OK: dist\SFCleaner.msix  (sideload: run setup_msix_trust.bat first)
exit /b 0

:makecert
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; try { $c = New-SelfSignedCertificate -Type Custom -Subject 'CN=SFCleaner Research' -KeyUsage DigitalSignature -FriendlyName 'SFCleaner test signing' -NotAfter (Get-Date).AddYears(3) -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}'); $p = ConvertTo-SecureString -String 'sf-cleaner-test' -Force -AsPlainText; Export-PfxCertificate -Cert $c -FilePath 'SFCleaner_TemporaryKey.pfx' -Password $p | Out-Null; Write-Host ('thumbprint: ' + $c.Thumbprint) } catch { Write-Host ('CERT ERROR: ' + $_.Exception.Message); exit 1 }"
exit /b %ERRORLEVEL%

:err
echo [MSIX MANUAL BUILD FAILED]
exit /b 1
