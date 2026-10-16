$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$compiler = Join-Path $projectRoot '.tools/inno/ISCC.exe'
if ($env:YKA_ISCC) { $compiler = $env:YKA_ISCC }
elseif (-not (Test-Path -LiteralPath $compiler)) { $compiler = (Get-Command ISCC -ErrorAction Stop).Source }
$driver = Join-Path $projectRoot 'vendor/installers/winfsp-2.1.25156.msi'
if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash -ne '073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a') { throw 'WinFsp package hash mismatch' }
if ((Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid') { throw 'WinFsp signature validation failed' }
$staging = Join-Path $projectRoot ('build/installer-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null
& $compiler ('/O' + $staging) (Join-Path $projectRoot 'installer/YkaVaultManager.iss')
if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed. Unpublished output: $staging" }
$outputs = @(Get-ChildItem -LiteralPath $staging -Filter '*-Setup-*.exe' -File)
if ($outputs.Count -ne 1) { throw 'Installer compilation did not produce exactly one installer' }
$destination = Join-Path $projectRoot ('dist/' + $outputs[0].Name)
if (Test-Path -LiteralPath $destination) {
    [System.IO.File]::Replace($outputs[0].FullName, $destination, (Join-Path $staging 'previous-installer.exe'))
} else {
    [System.IO.File]::Move($outputs[0].FullName, $destination)
}
Write-Output "Published installer: $destination"
