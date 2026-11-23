# WinNotify.sys -> Python bridge -> single-file .exe
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File py\build.ps1

param(
    [string]$Python = "py",
    [string]$Name = "winnotify-cli",
    [switch]$Onedir,
    [switch]$NoConsole
)

$ErrorActionPreference = "Stop"
$Here = Split-Path $MyInvocation.MyCommand.Path -Parent

Write-Host "=== building $Name.exe ===" -ForegroundColor Cyan
Push-Location $Here
try {
    & $Python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[...] installing PyInstaller" -ForegroundColor Yellow
        & $Python -m pip install --upgrade "pyinstaller>=6.6"
    }

    $pyi = @(
        "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", $Name,
        "--distpath", "dist",
        "--workpath", "build",
        "--specpath", "."
    )
    if (-not $Onedir) { $pyi += "--onefile" }
    if ($NoConsole) { $pyi += "--noconsole" } else { $pyi += "--console" }
    $pyi += "cli.py"

    Write-Host "[...] $Python $($pyi -join ' ')" -ForegroundColor DarkGray
    & $Python @pyi
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }

    $exe = Join-Path $Here "dist\$Name.exe"
    if (Test-Path $exe) {
        Write-Host "[OK] $exe  ($([math]::Round((Get-Item $exe).Length / 1MB, 1)) MB)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Ship next to the exe:" -ForegroundColor Cyan
        Write-Host "  WinNotify.sys     (or signeddrv.sys)"
        Write-Host "  winnotify.json    (any offset/ioctl overrides -- see README.md)"
        Write-Host ""
        Write-Host "Example:" -ForegroundColor Cyan
        Write-Host "  .\dist\$Name.exe PlantsVsZombies.exe 0x0019A5B8 999"
    } else {
        throw "output exe not found"
    }
}
finally {
    Pop-Location
}
