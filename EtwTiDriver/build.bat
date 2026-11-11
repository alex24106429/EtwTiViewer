@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: build.bat — Build and test-sign EtwTiDriver
::
:: Prerequisites:
::   - Visual Studio 2022 (MSBuild on PATH)
::   - Windows Driver Kit (WDK) installed and matched to VS
::   - signtool.exe on PATH (Windows SDK)
::
:: The certificate is NOT installed to any machine store.
:: Copy EtwTiTestCert.cer to your target VM and install it there:
::   - Trusted Root Certification Authorities
::   - Trusted Publishers
:: Then enable test-signing on the VM:
::   bcdedit /set testsigning on  (reboot required)
:: ============================================================

set SCRIPT_DIR=%~dp0
set CERT_NAME=EtwTiTestCert
set PFX_FILE=%SCRIPT_DIR%EtwTiTestCert.pfx
set CER_FILE=%SCRIPT_DIR%EtwTiTestCert.cer
set SYS_FILE=%SCRIPT_DIR%x64\Release\EtwTiDriver.sys
:: PFX password — used only during the build, not installed anywhere
set PFX_PASS=EtwTiBuild1

:: ------------------------------------------------------------
:: Step 1: Build the driver with MSBuild
:: ------------------------------------------------------------
echo [1/3] Building EtwTiDriver...
msbuild "%SCRIPT_DIR%EtwTiDriver.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Build /m
if %ERRORLEVEL% neq 0 (
    echo ERROR: MSBuild failed. Ensure WDK and VS 2022 are installed.
    exit /b 1
)

:: ------------------------------------------------------------
:: Step 2: Create self-signed cert (files only — nothing installed)
::
:: The PFX is reused across builds so the same cert can be installed
:: once in the VM and remain valid for all subsequent driver builds.
:: Delete EtwTiTestCert.pfx manually if you need to rotate the cert.
::
:: NOTE: goto used instead of if-else block because the PowerShell
:: command contains many parentheses that confuse cmd's block parser
:: even inside double-quoted strings.
:: ------------------------------------------------------------
if exist "%PFX_FILE%" goto :cert_reuse

echo [2/3] Creating self-signed test certificate (not installed to store)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$cert = New-SelfSignedCertificate -Subject 'CN=%CERT_NAME%' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -NotAfter (Get-Date).AddYears(14) -HashAlgorithm SHA256; $pwd = ConvertTo-SecureString -String '%PFX_PASS%' -Force -AsPlainText; Export-PfxCertificate -Cert $cert -FilePath '%PFX_FILE%' -Password $pwd -Force | Out-Null; Export-Certificate -Cert $cert -FilePath '%CER_FILE%' -Force | Out-Null; Remove-Item -Path ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force; Write-Host ('  Thumbprint: ' + $cert.Thumbprint)"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Certificate creation failed.
    exit /b 1
)
echo   PFX: %PFX_FILE%
echo   CER: %CER_FILE%  -- install this in your VM once
goto :cert_done

:cert_reuse
echo [2/3] Reusing existing certificate -- delete %PFX_FILE% to rotate

:cert_done

:: ------------------------------------------------------------
:: Step 3: Sign the driver binary using the PFX directly
:: No catalog needed — this driver is loaded via sc create, not PnP.
:: ------------------------------------------------------------
echo [3/3] Signing driver binary...
signtool sign /v /f "%PFX_FILE%" /p %PFX_PASS% /fd SHA256 /t http://timestamp.digicert.com "%SYS_FILE%"
if %ERRORLEVEL% neq 0 (
    echo WARNING: Timestamp server unavailable. Signing without timestamp...
    signtool sign /v /f "%PFX_FILE%" /p %PFX_PASS% /fd SHA256 "%SYS_FILE%"
    if %ERRORLEVEL% neq 0 (
        echo ERROR: signtool failed.
        exit /b 1
    )
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo  Driver : %SYS_FILE%
echo  Cert   : %CER_FILE%
echo.
echo  On the target VM (as Administrator):
echo    1. Install %CERT_NAME%.cer into:
echo         Trusted Root Certification Authorities (local machine)
echo         Trusted Publishers (local machine)
echo    2. bcdedit /set testsigning on  ^(reboot^)
echo    3. sc create EtwTiDriver type= kernel start= demand binPath= "^<path^>\x64\Release\EtwTiDriver.sys"
echo    4. sc start EtwTiDriver
echo ============================================================
endlocal
