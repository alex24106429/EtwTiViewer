#Requires -Version 5.1
<#
.SYNOPSIS
    Build EtwTiViewer (Release|x64), cloning ImGui if necessary.

.DESCRIPTION
    Builds the viewer, which consumes Threat-Intelligence from the AutoLogger
    session registered by install_autologger.ps1.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build.ps1
#>
[CmdletBinding()]
param(
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath

# ---------------------------------------------------------------------------
# ImGui (docking branch) — the viewer renders with it.
# ---------------------------------------------------------------------------
$imguiDir = Join-Path $root 'third_party\imgui'
if (-not (Test-Path (Join-Path $imguiDir 'imgui.h'))) {
    Write-Host 'Cloning ImGui (docking branch)...' -ForegroundColor Cyan
    New-Item -ItemType Directory -Path (Split-Path $imguiDir) -Force | Out-Null
    git clone --depth 1 --branch docking https://github.com/ocornut/imgui.git $imguiDir
    if ($LASTEXITCODE -ne 0) { throw 'git clone of ImGui failed' }
}

# ---------------------------------------------------------------------------
# Locate MSBuild
# ---------------------------------------------------------------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * `
        -requires Microsoft.Component.MSBuild `
        -property installationPath
}

$msbuild = $null
if ($vsPath) {
    $candidate = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (Test-Path $candidate) { $msbuild = $candidate }
}

if (-not $msbuild) {
    $candidates = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\17\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )
    foreach ($pattern in $candidates) {
        $hit = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $msbuild = $hit.FullName; $vsPath = Split-Path (Split-Path (Split-Path (Split-Path $hit.FullName))); break }
    }
}

if (-not $msbuild) {
    throw 'MSBuild not found. Install Visual Studio 2022/2026 Build Tools with C++ and retry.'
}

# ---------------------------------------------------------------------------
# Pick a toolset that is actually installed (v143 on VS2022, v145 on VS2026)
# ---------------------------------------------------------------------------
$toolset = $null
if ($vsPath) {
    $msvc = Get-ChildItem (Join-Path $vsPath 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($msvc) {
        $minor = ([version]$msvc.Name).Minor
        $toolset = switch ($minor) {
            { $_ -ge 50 } { 'v145'; break }
            { $_ -ge 40 } { 'v143'; break }
            { $_ -ge 30 } { 'v143'; break }
            { $_ -ge 20 } { 'v142'; break }
            { $_ -ge 10 } { 'v141'; break }
            default       { 'v140' }
        }
    }
}

$project = Join-Path $root 'EtwTiViewer\EtwTiViewer.vcxproj'
$common  = @($project, "-p:Configuration=$Configuration", '-p:Platform=x64', '-v:m')

$toolsetDisplay = if ($toolset) { $toolset } else { 'project default' }
Write-Host "MSBuild : $msbuild" -ForegroundColor Gray
Write-Host "Toolset : $toolsetDisplay" -ForegroundColor Gray

$toolsetArg = @()
if ($toolset) { $toolsetArg = @("-p:PlatformToolset=$toolset") }

$output = & $msbuild @common @toolsetArg 2>&1
$output | ForEach-Object { $_ }

if ($LASTEXITCODE -ne 0 -and $toolset -ne 'v143') {
    Write-Host 'Retrying with the project default toolset (v143)...' -ForegroundColor Yellow
    $output = & $msbuild @common 2>&1
    $output | ForEach-Object { $_ }
}

if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }

$exe = Join-Path $root "EtwTiViewer\x64\$Configuration\EtwTiViewer.exe"
if (-not (Test-Path $exe)) { throw "Build reported success but $exe is missing" }

Write-Host ''
Write-Host "Built: $exe" -ForegroundColor Green
