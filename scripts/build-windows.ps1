param(
    [string]$Python = ".\.venv\Scripts\python.exe",
    [string]$OutputDirectory = ".\dist",
    [string]$Go = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonPath = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $Python))
$DistPath = [IO.Path]::GetFullPath((Join-Path $ProjectRoot $OutputDirectory))
$EngineBinary = Join-Path $ProjectRoot "cli\src\netra\bin\netra-engine.exe"

if (-not [Environment]::Is64BitProcess) {
    throw "La build 1.0.0 requiere un proceso de 64 bits."
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "No se encontró Python en $PythonPath"
}
if ([string]::IsNullOrWhiteSpace($Go)) {
    $GoCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -ne $GoCommand) {
        $Go = $GoCommand.Source
    }
    else {
        $Go = Join-Path $env:ProgramFiles "Go\bin\go.exe"
    }
}
if (-not (Test-Path -LiteralPath $Go -PathType Leaf)) {
    throw "No se encontró Go; usa -Go con la ruta de go.exe."
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $EngineBinary) | Out-Null
New-Item -ItemType Directory -Force -Path $DistPath | Out-Null

& $Go -C (Join-Path $ProjectRoot "engine") test ./...
& $Go -C (Join-Path $ProjectRoot "engine") vet ./...
& $Go -C (Join-Path $ProjectRoot "engine") build -buildvcs=false -trimpath -ldflags "-s -w" -o $EngineBinary ./cmd/netra-engine
& $PythonPath -m pytest (Join-Path $ProjectRoot "cli\tests")
& $PythonPath -m build --wheel --outdir $DistPath $ProjectRoot

$Wheel = Get-ChildItem -LiteralPath $DistPath -Filter "netra-1.0.0-*-win_*.whl" |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -eq $Wheel) {
    throw "No se generó el wheel Windows esperado."
}
& $PythonPath (Join-Path $ProjectRoot "scripts\verify_wheel.py") $Wheel.FullName

$SmokeRoot = Join-Path ([IO.Path]::GetTempPath()) ("netra-1.0.0-smoke-" + [guid]::NewGuid().ToString("N"))
$ResolvedSmokeRoot = [IO.Path]::GetFullPath($SmokeRoot)
$ResolvedTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not $ResolvedSmokeRoot.StartsWith($ResolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Split-Path -Leaf $ResolvedSmokeRoot).StartsWith("netra-1.0.0-smoke-", [StringComparison]::Ordinal)) {
    throw "La ruta temporal de smoke test no es segura: $ResolvedSmokeRoot"
}
try {
    & $PythonPath -m venv $ResolvedSmokeRoot
    $SmokePython = Join-Path $ResolvedSmokeRoot "Scripts\python.exe"
    & $SmokePython -m pip install --disable-pip-version-check $Wheel.FullName
    & $SmokePython -m pip check
    & $SmokePython -m netra --version
    & $SmokePython -m netra doctor --json
}
finally {
    if (Test-Path -LiteralPath $ResolvedSmokeRoot) {
        Remove-Item -LiteralPath $ResolvedSmokeRoot -Recurse -Force
    }
}

$ChecksumPath = Join-Path $DistPath "SHA256SUMS.txt"
$Hash = Get-FileHash -LiteralPath $Wheel.FullName -Algorithm SHA256
"$($Hash.Hash.ToLowerInvariant())  $($Wheel.Name)" | Set-Content -LiteralPath $ChecksumPath -Encoding ascii
Write-Host "Paquete listo: $($Wheel.FullName)"
Write-Host "Checksum: $ChecksumPath"
