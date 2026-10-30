# build.ps1 - compiles pesymp.exe from Program.cs.
# Run: powershell -ExecutionPolicy Bypass -File build.ps1 [-OutDir .\bin]
#
# Compiler lookup order:
#   1) csc.exe from .NET Framework (present on any Windows)
#   2) Roslyn csc.exe from Visual Studio / Build Tools
#   3) fallback: Add-Type -OutputType ConsoleApplication
param(
    [string]$OutDir = ".",
    [string]$Source = "$PSScriptRoot\Program.cs"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Source)) { throw "Source not found: $Source" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutExe = Join-Path $OutDir "pesymp.exe"

function Find-Csc {
    # .NET Framework (32/64 bit)
    $fw = @(
        "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    ) | Where-Object { Test-Path $_ }
    if ($fw) { return $fw[0] }

    # Roslyn from VS / Build Tools
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsRoot = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VBC.Csc `
            -property installationPath 2>$null
        if ($vsRoot) {
            $roslyn = Get-ChildItem -Path (Join-Path $vsRoot "MSBuild\Current\Bin\Roslyn\csc.exe") -ErrorAction SilentlyContinue
            if ($roslyn) { return $roslyn.FullName }
        }
    }
    return $null
}

$csc = Find-Csc
if ($csc) {
    Write-Host "Compiling with: $csc"
    & $csc /nologo /optimize+ /out:"$OutExe" "$Source"
    if ($LASTEXITCODE -ne 0) { throw "csc exited with code $LASTEXITCODE" }
}
else {
    # Fallback: compile via Add-Type (Windows PowerShell 5.1)
    Write-Host "csc.exe not found, using Add-Type..."
    $code = Get-Content $Source -Raw
    Add-Type -TypeDefinition $code `
        -OutputAssembly $OutExe `
        -OutputType ConsoleApplication
}

Write-Host ""
Write-Host "Done: $OutExe" -ForegroundColor Green
Write-Host "Smoke test:"
& $OutExe -i CreateFile "$env:WINDIR\System32\kernel32.dll"
