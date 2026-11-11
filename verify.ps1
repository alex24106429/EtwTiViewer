#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end verification: attach EtwTiViewer headlessly to the protected
    AutoLogger session, provoke remote-memory activity and assert that live
    Microsoft-Windows-Threat-Intelligence events arrive.

.DESCRIPTION
    Requires:
      * install_autologger.ps1 already run, followed by a reboot
      * EtwTiViewer built (build.ps1)

    No kernel debugger, PPL, driver or test-signing is used.

.PARAMETER Seconds
    Capture duration per attach.

.PARAMETER Cycles
    Number of attach/detach cycles in the same process (tests re-attach).

.PARAMETER Keywords
    Client-side keyword filter.  The default selects the remote variants that
    process-injection activity produces, keeping the log small.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\verify.ps1
#>
[CmdletBinding()]
param(
    [int]    $Seconds  = 20,
    [int]    $Cycles   = 1,
    [string] $Keywords = '0x3FA5444',
    [string] $SessionName = '0MyThreatIntelTrace'
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('etwti_verify_' + [guid]::NewGuid().ToString('N') + '.log')

    $invoke = "& '$PSCommandPath' -Seconds $Seconds -Cycles $Cycles " +
              "-Keywords '$Keywords' -SessionName '$SessionName'"
    $command = "$invoke *> '$temp'; exit `$LASTEXITCODE"

    Write-Host 'Requesting elevation...' -ForegroundColor Yellow
    $p = Start-Process powershell -Verb RunAs `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) `
        -Wait -PassThru

    if (Test-Path $temp) {
        Get-Content $temp | ForEach-Object { Write-Output $_ }
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
    }
    exit $p.ExitCode
}

$root = $PSCommandPath | Split-Path -Parent
$exe  = Join-Path $root 'EtwTiViewer\x64\Release\EtwTiViewer.exe'
$log  = Join-Path $root 'verify_capture.jsonl'
$err  = Join-Path $root 'verify_capture.stderr.txt'

if (-not (Test-Path $exe)) {
    throw "EtwTiViewer.exe not found at $exe. Run build.ps1 first."
}

Remove-Item $log, $err -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Show session readiness first (this also validates the registry key).
# ---------------------------------------------------------------------------
& (Join-Path $root 'install_autologger.ps1') -Status -SessionName $SessionName
if ($LASTEXITCODE -ne 0) {
    throw 'AutoLogger session is not registered. Run install_autologger.ps1 and reboot.'
}

# ---------------------------------------------------------------------------
# Activity generator: remote allocation / write / protect / map / thread.
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class TiVerifyActivity
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, IntPtr size, uint type, uint protect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, IntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint newProtect, out uint oldProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buffer, IntPtr size, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attrs, IntPtr stack,
                                            IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    public static int Run(int pid, int rounds, int delayMs)
    {
        const uint Access = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0400;
        IntPtr h = OpenProcess(Access, false, pid);
        if (h == IntPtr.Zero) return -1;

        byte[] stub = { 0xC3, 0x90, 0x90, 0x90 };
        int ok = 0;

        for (int i = 0; i < rounds; i++)
        {
            IntPtr mem = VirtualAllocEx(h, IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40);
            if (mem == IntPtr.Zero) break;

            IntPtr written;
            uint old;
            WriteProcessMemory(h, mem, stub, (IntPtr)stub.Length, out written);
            VirtualProtectEx(h, mem, (IntPtr)0x1000, 0x04, out old);

            uint tid;
            IntPtr thread = CreateRemoteThread(h, IntPtr.Zero, IntPtr.Zero,
                                               mem, IntPtr.Zero, 0x4, out tid);
            if (thread != IntPtr.Zero) CloseHandle(thread);

            VirtualFreeEx(h, mem, IntPtr.Zero, 0x8000);
            ok++;

            if (delayMs > 0) Thread.Sleep(delayMs);
        }

        CloseHandle(h);
        return ok;
    }
}
'@

Write-Host ''
Write-Host "Capturing $Seconds s x $Cycles cycle(s)... (session $SessionName)" -ForegroundColor Cyan

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = $exe
$psi.Arguments              = "--capture $Seconds --cycles $Cycles --keywords $Keywords --session `"$SessionName`" --log `"$log`""
$psi.UseShellExecute        = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.CreateNoWindow         = $true
$psi.WorkingDirectory       = Split-Path $exe

$viewer = [System.Diagnostics.Process]::new()
$viewer.StartInfo = $psi
[void]$viewer.Start()

Start-Sleep -Seconds 2

$target = Start-Process cmd.exe -ArgumentList '/c', 'ping -n 120 127.0.0.1 >nul' -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 500

$delay  = 300
$rounds = [Math]::Max(4, [int]((($Seconds * $Cycles) - 4) * 1000 / $delay))
$activity = [TiVerifyActivity]::Run($target.Id, $rounds, $delay)

if (-not $viewer.WaitForExit(($Seconds * $Cycles + 30) * 1000)) {
    $viewer.Kill()
    $viewer.WaitForExit()
    Write-Host 'Viewer timed out' -ForegroundColor Red
}
Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue

$stderrText = $viewer.StandardError.ReadToEnd()
Set-Content -Path $err -Value $stderrText -Encoding ascii

Write-Host ''
Write-Host "Activity rounds : $activity"
Write-Host "Viewer exit     : $($viewer.ExitCode)"
Write-Host ''
Write-Host '--- viewer diagnostics ---' -ForegroundColor Gray
Get-Content $err | ForEach-Object { Write-Host "  $_" }

if (-not (Test-Path $log)) {
    throw "No log produced ($log)."
}

$lines   = @(Get-Content $log)
$attach  = @($lines | Where-Object { $_ -match '"attach":true' })[0]
$summary = @($lines | Where-Object { $_ -match '"summary":true' })[-1]
$events  = @($lines | Where-Object { $_ -match '"name":"' })

Write-Host ''
Write-Host "JSONL lines : $($lines.Count)  (events: $($events.Count))"

if ($attach)  { Write-Host "Attach      : $attach"  -ForegroundColor Green }
if ($summary) { Write-Host "Summary     : $summary" }

Write-Host ''
Write-Host '--- event mix ---' -ForegroundColor Gray
$events |
    ForEach-Object { if ($_ -match '"name":"([^"]+)"') { $Matches[1] } } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 15 |
    ForEach-Object { Write-Host ("  {0,-42} x{1}" -f $_.Name, $_.Count) }

$viewerEvents = 0
if ($summary -and $summary -match '"events":(\d+)') { $viewerEvents = [int]$Matches[1] }

Write-Host ''
if ($viewer.ExitCode -eq 0 -and $viewerEvents -gt 0) {
    Write-Host 'SUCCESS: live Threat-Intelligence events received.' -ForegroundColor Green
    Write-Host '         No PPL, no driver, no kernel patch.' -ForegroundColor Green
    exit 0
}

Write-Host 'FAILURE: no Threat-Intelligence events were received.' -ForegroundColor Red
Write-Host '  * Did you reboot after install_autologger.ps1?' -ForegroundColor Yellow
Write-Host '  * Does install_autologger.ps1 -Status report PROTECTED?' -ForegroundColor Yellow
exit 1
