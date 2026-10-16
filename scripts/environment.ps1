# Dot-source from build/package scripts. Never changes the machine/user environment.
$projectRoot = Split-Path -Parent $PSScriptRoot
$localCargo = Join-Path $projectRoot '.tools/cargo/bin'
if (Test-Path -LiteralPath (Join-Path $localCargo 'cargo.exe')) {
    $env:CARGO_HOME = Join-Path $projectRoot '.tools/cargo'
    $env:RUSTUP_HOME = Join-Path $projectRoot '.tools/rustup'
    $env:PATH = $localCargo + ';' + $env:PATH
}
if ($env:YKA_MINGW_BIN) { $env:PATH = $env:YKA_MINGW_BIN + ';' + $env:PATH }
if ($env:YKA_PYTHON) { $pythonExe = $env:YKA_PYTHON }
elseif (Test-Path -LiteralPath (Join-Path $projectRoot '.tools/python313/python.exe')) {
    $pythonExe = Join-Path $projectRoot '.tools/python313/python.exe'
} elseif (Test-Path -LiteralPath (Join-Path $projectRoot '.venv/Scripts/python.exe')) {
    $pythonExe = Join-Path $projectRoot '.venv/Scripts/python.exe'
} else { $pythonExe = (Get-Command python -ErrorAction Stop).Source }
$env:PYTHONUTF8 = '1'
$env:PYTHONPATH = Join-Path $projectRoot 'src'

