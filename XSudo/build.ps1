#requires -Version 7
param([switch]$Clean, [switch]$Install)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
try {
    $env:RUSTFLAGS = '-C target-feature=+crt-static'
    if ($Clean) { cargo clean }
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }

    $exe = Join-Path $root 'target\release\XSudo.exe'
    $item = Get-Item -LiteralPath $exe
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash

    $ascii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exe))
    $bad = @()
    foreach ($pat in 'vcruntime', 'msvcp', 'msvcr', 'api-ms-win-crt') {
        $found = [regex]::Matches($ascii, "(?i)[a-z0-9\-]*$pat[a-z0-9\-]*\.dll") | ForEach-Object { $_.Value } | Select-Object -Unique
        if ($found) { $bad += $found }
    }
    if ($bad.Count -gt 0) {
        throw "Static CRT check failed: XSudo.exe imports $($bad -join ', '). Ensure +crt-static is active."
    }

    Write-Host ''
    Write-Host "Path   : $($item.FullName)"
    Write-Host "Size   : $($item.Length) bytes"
    Write-Host "SHA256 : $hash"
    Write-Host "CRT    : static (no vcruntime/msvcp/msvcr/api-ms-win-crt imports)"

    if ($Install) {
        $dest = Join-Path $root '..\resources\XSudo.exe'
        Copy-Item -LiteralPath $exe -Destination $dest -Force
        $destHash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
        if ($destHash -ne $hash) { throw "Install copy hash mismatch: $destHash" }
        Write-Host "Install: $((Resolve-Path -LiteralPath $dest).Path)"
        Write-Host "SHA256 : $destHash"
    }
}
finally {
    Pop-Location
}
