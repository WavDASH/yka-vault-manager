$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'environment.ps1')
$definition = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/YkaVaultManager.iss') -Raw
$releaseVersion = [regex]::Match($definition, 'AppVersion "([0-9]+\.[0-9]+\.[0-9]+)"').Groups[1].Value
if (-not $releaseVersion) { throw 'Invalid application version' }
$releaseDirectory = Join-Path $projectRoot "dist/portable-$releaseVersion"
$targetDirectory = Join-Path $releaseDirectory 'YkaVaultManager'
$targetPrefix = [System.IO.Path]::GetFullPath($targetDirectory).TrimEnd('\') + '\'
$running = Get-CimInstance Win32_Process -Filter "Name = 'YkaVaultManager.exe'" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($targetPrefix, [System.StringComparison]::OrdinalIgnoreCase) }
if ($running) { throw 'This release is running. Exit it safely before rebuilding the same version.' }
Push-Location -LiteralPath $projectRoot
try {
    & $pythonExe scripts/build_icons.py
    if ($LASTEXITCODE -ne 0) { throw 'Icon generation failed' }
    & $pythonExe -m PyInstaller --distpath $releaseDirectory --noconfirm --onedir --windowed --name YkaVaultManager --icon assets/yka.ico --paths src `
        --hidden-import yka.worker --hidden-import yka.piv_setup --hidden-import smartcard.scard.scard --hidden-import win32timezone `
        --add-binary 'native/target/release/yka-crypto.exe;native/target/release' `
        --add-binary 'vendor/securefs/securefs.exe;vendor/securefs' `
        --add-binary 'vendor/age-plugin-yubikey-source/target/release/age-plugin-yubikey.exe;vendor/age-plugin-yubikey-source/target/release' `
        --add-data 'README.md;.' --add-data 'LICENSE;.' --add-data 'docs/THIRD_PARTY.md;docs' `
        --add-data 'docs/licenses;docs/licenses' --add-data 'docs/dependency-inventory.json;docs' `
        --add-data 'vendor/dependencies.json;vendor' app.py
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
} finally { Pop-Location }
