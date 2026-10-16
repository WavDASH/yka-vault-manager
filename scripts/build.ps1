$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'environment.ps1')
Push-Location -LiteralPath $projectRoot
try {
    cargo build --locked --release --manifest-path native/Cargo.toml
    if ($LASTEXITCODE -ne 0) { throw 'Native build failed' }
    cargo build --locked --release --manifest-path vendor/age-plugin-yubikey-source/Cargo.toml
    if ($LASTEXITCODE -ne 0) { throw 'Plugin build failed' }
    & $pythonExe -m compileall -q src
    if ($LASTEXITCODE -ne 0) { throw 'Python validation failed' }
} finally { Pop-Location }
