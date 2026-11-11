#Requires -Version 5.1
<#
.SYNOPSIS
    Register (or remove) the AutoLogger session that lets EtwTiViewer consume
    Microsoft-Windows-Threat-Intelligence without PPL, a driver or a kernel patch.

.DESCRIPTION
    The kernel starts AutoLogger sessions at boot with no caller identity, so
    enabling the Threat-Intelligence provider never hits the
    PS_PROTECTED_ANTIMALWARE_LIGHT check.  EtwTiViewer then attaches to the
    resulting SecurityTrace-protected real-time session and detours
    sechost!ControlTraceW in its own process.

    This script only writes the registry key.  A reboot is required for the
    kernel to create the session.

.PARAMETER Remove
    Delete the AutoLogger key (reboot afterwards to tear the session down).

.PARAMETER Status
    Show the registry configuration and query the live session; no changes.

.PARAMETER SessionName
    AutoLogger session name.  Default: 0MyThreatIntelTrace (the leading '0'
    makes the session sort first, which keeps the logger-ID heuristic stable).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install_autologger.ps1
    # ... reboot ...
    powershell -ExecutionPolicy Bypass -File .\install_autologger.ps1 -Status
#>
[CmdletBinding()]
param(
    [switch] $Remove,
    [switch] $Status,
    [string] $SessionName = '0MyThreatIntelTrace'
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Self-elevate: HKLM\SYSTEM\...\Autologger is only readable/writable as admin.
# ---------------------------------------------------------------------------
if (-not (Test-Admin)) {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('etwti_setup_' + [guid]::NewGuid().ToString('N') + '.log')

    $invoke = "& '$PSCommandPath'"
    if ($Remove) { $invoke += ' -Remove' }
    if ($Status) { $invoke += ' -Status' }
    if ($SessionName -ne '0MyThreatIntelTrace') {
        $invoke += " -SessionName '$SessionName'"
    }
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

$autoLoggerRoot = 'SYSTEM\CurrentControlSet\Control\WMI\Autologger'
$sessionKey     = "HKLM:\$autoLoggerRoot\$SessionName"
$providerKey    = Join-Path $sessionKey '{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}'

# MatchAnyKeyword for the AutoLogger provider subkey.  Stored as REG_BINARY(8):
# 0x000005ffffffffff, i.e. every Threat-Intelligence keyword bit.
$matchAnyKeyword = [byte[]](0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x05, 0x00, 0x00)

function Invoke-ControlTraceQuery([string] $name) {
    if (-not ([System.Management.Automation.PSTypeName]'EtwProbe').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class EtwProbe
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint ControlTraceW(ulong handle, string name,
                                             IntPtr props, uint code);

    // Returns "PROTECTED" (5), "RUNNING" (0 + name), "NOT_FOUND" (4201) or
    // "ERROR <n>".
    public static string Query(string name)
    {
        IntPtr p = Marshal.AllocHGlobal(0x1078);
        try
        {
            for (int i = 0; i < 0x1078; i++) Marshal.WriteByte(p, i, 0);
            Marshal.WriteInt32(p, 0x00, 0x1078);   // Wnode.BufferSize
            Marshal.WriteInt32(p, 0x2C, 0x20000);  // WNODE_FLAG_TRACED_GUID

            uint rc = ControlTraceW(0, name, p, 0 /* QUERY */);
            if (rc == 5)   return "PROTECTED";
            if (rc == 4201) return "NOT_FOUND";
            if (rc != 0)   return "ERROR " + rc;

            int nameOffset = Marshal.ReadInt32(p, 0x74); // LoggerNameOffset
            string live = Marshal.PtrToStringUni(
                new IntPtr(p.ToInt64() + nameOffset));
            return "RUNNING (" + live + ")";
        }
        finally
        {
            Marshal.FreeHGlobal(p);
        }
    }
}
'@
    }

    return [EtwProbe]::Query($name)
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
if ($Status) {
    Write-Host "AutoLogger session: $SessionName" -ForegroundColor Cyan

    if (-not (Test-Path $sessionKey)) {
        Write-Host '  Registry : NOT REGISTERED' -ForegroundColor Red
        Write-Host "  Run this script without -Status, then reboot."
        exit 1
    }

    $values = Get-ItemProperty -Path $sessionKey
    'Start', 'LogFileMode', 'BufferSize', 'ClockType', 'FlushTimer',
    'MaximumBuffers', 'MinimumBuffers', 'GUID' | ForEach-Object {
        $v = $values.$_
        if ($_ -eq 'LogFileMode' -and $null -ne $v) {
            $v = ('0x{0:X} ({1})' -f $v, $(if ($v -band 0x100) { 'real-time' } else { 'not real-time' }))
        }
        Write-Host ("  {0,-15}: {1}" -f $_, $v)
    }

    if (Test-Path $providerKey) {
        $provider = Get-ItemProperty -Path $providerKey
        $keyword  = $provider.MatchAnyKeyword
        if ($keyword -is [byte[]]) {
            $keyword = [BitConverter]::ToUInt64($keyword, 0)
        } else {
            $keyword = [Convert]::ToUInt64($keyword)
        }
        Write-Host ("  TI provider    : Enabled={0} Level={1} MatchAnyKeyword=0x{2:X}" -f `
            $provider.Enabled, $provider.EnableLevel, $keyword)
    } else {
        Write-Host '  TI provider    : MISSING' -ForegroundColor Red
    }

    $state = Invoke-ControlTraceQuery $SessionName
    switch -Wildcard ($state) {
        'PROTECTED' {
            Write-Host '  Live session   : PROTECTED (SecurityTrace) - ready to attach' -ForegroundColor Green
        }
        'RUNNING*' {
            Write-Host "  Live session   : $state" -ForegroundColor Green
        }
        'NOT_FOUND' {
            Write-Host '  Live session   : NOT RUNNING - reboot after installing the key' -ForegroundColor Yellow
        }
        default {
            Write-Host "  Live session   : $state" -ForegroundColor Yellow
        }
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------
if ($Remove) {
    if (Test-Path $sessionKey) {
        Remove-Item -Path $sessionKey -Recurse -Force
        Write-Host "Removed $sessionKey" -ForegroundColor Yellow
        Write-Host 'Reboot to tear down the running session.' -ForegroundColor Yellow
    } else {
        Write-Host "Nothing to remove ($SessionName is not registered)." -ForegroundColor Gray
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
Write-Host "Registering AutoLogger session '$SessionName'..." -ForegroundColor Cyan

if (-not (Test-Path $sessionKey)) {
    New-Item -Path $sessionKey -Force | Out-Null
}

# Session-wide settings.  LogFileMode 0x100 = EVENT_TRACE_REAL_TIME_MODE only.
$sessionValues = [ordered]@{
    Age            = 1
    BufferSize     = 0x40
    ClockType      = 1
    FlushTimer     = 1
    GUID           = '{7F6E5C2A-1B9D-4E3A-8C61-2F4B8A91D7C8}'
    LogFileMode    = 0x100
    MaximumBuffers = 0x10
    MinimumBuffers = 0
    Start          = 1
    Status         = 0
}

foreach ($name in $sessionValues.Keys) {
    $type = if ($sessionValues[$name] -is [string]) { 'String' } else { 'DWord' }
    New-ItemProperty -Path $sessionKey -Name $name -Value $sessionValues[$name] `
        -PropertyType $type -Force | Out-Null
}

# Provider subkey: enable Microsoft-Windows-Threat-Intelligence at boot.
if (-not (Test-Path $providerKey)) {
    New-Item -Path $providerKey -Force | Out-Null
}

New-ItemProperty -Path $providerKey -Name 'Enabled'         -Value 1               -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $providerKey -Name 'EnableLevel'     -Value 4               -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $providerKey -Name 'MatchAnyKeyword' -Value $matchAnyKeyword -PropertyType Binary -Force | Out-Null
New-ItemProperty -Path $providerKey -Name 'Status'          -Value 0               -PropertyType DWord  -Force | Out-Null

Write-Host ''
Write-Host 'Installed.  The session is created by the kernel at boot.' -ForegroundColor Green
Write-Host ''
Write-Host 'NEXT:' -ForegroundColor Yellow
Write-Host '  1. reboot'
Write-Host '  2. run the viewer (it self-elevates):'
Write-Host '       EtwTiViewer\EtwTiViewer\x64\Release\EtwTiViewer.exe'
Write-Host '     or verify headlessly:'
Write-Host '       powershell -ExecutionPolicy Bypass -File .\verify.ps1'
Write-Host ''
Write-Host "Confirm after reboot:  .\install_autologger.ps1 -Status" -ForegroundColor Gray
