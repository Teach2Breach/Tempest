# End-to-end: Anvil (HTTPS) + win-stargate beacon.exe check-in on localhost.
# Used by .github/workflows/windows-smoke.yml and documented for manual lab runs.

$ErrorActionPreference = "Stop"

function Get-WebResponseText($Response) {
    $content = $Response.Content
    if ($content -is [byte[]]) {
        return [Text.Encoding]::UTF8.GetString($content)
    }
    return [string]$content
}

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$AnvilDir = Join-Path $RepoRoot "Anvil"
$WinDir = Join-Path $RepoRoot "imps\win-stargate"
$WorkDir = Join-Path $env:TEMP "tempest-smoke"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$ImplantPort = 8444
$ConduitPort = 8445

# TLS material (self-signed)
$CertDir = Join-Path $WorkDir "cert"
New-Item -ItemType Directory -Force -Path $CertDir | Out-Null
$CertPem = Join-Path $CertDir "cert.pem"
$KeyPem = Join-Path $CertDir "key.pem"
& openssl req -x509 -newkey rsa:2048 -keyout $KeyPem -out $CertPem -days 1 -nodes -subj "/CN=localhost" 2>$null
if (-not (Test-Path $CertPem)) {
    throw "openssl not available; install Git for Windows OpenSSL or add openssl to PATH"
}

Push-Location $AnvilDir
try {
    # Build Anvil
    cargo build --release 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "Anvil build failed" }

    # Test config (non-privileged ports)
    @"
[[users]]
username = "forge"
password = "forge"

[cert]
private_key = "$($KeyPem -replace '\\','/')"
certificate = "$($CertPem -replace '\\','/')"

[crypt]
LITCRYPT_ENCRYPT_KEY = "ageofmachine"

[server]
implant_port = $ImplantPort
conduit_port = $ConduitPort
outputs_max_rows = 0

[build]
toolchain = "1.85.0"
"@ | Set-Content -Path (Join-Path $WorkDir "config.toml") -Encoding UTF8

    Copy-Item (Join-Path $WorkDir "config.toml") (Join-Path $AnvilDir "config.toml") -Force
    Remove-Item -ErrorAction SilentlyContinue (Join-Path $AnvilDir "aes_key.bin")
    Remove-Item -ErrorAction SilentlyContinue (Join-Path $AnvilDir "my_database.db")

    $AnvilLog = Join-Path $WorkDir "anvil.log"
    $AnvilErrLog = Join-Path $WorkDir "anvil.err.log"
    $AnvilProc = Start-Process -FilePath (Join-Path $AnvilDir "target\release\anvil.exe") `
        -WorkingDirectory $AnvilDir -PassThru -RedirectStandardOutput $AnvilLog -RedirectStandardError $AnvilErrLog
    Start-Sleep -Seconds 4
    if ($AnvilProc.HasExited) {
        Get-Content $AnvilLog, $AnvilErrLog -ErrorAction SilentlyContinue
        throw "Anvil exited early"
    }

    # Read AES_KEY from log (Anvil prints encoded AES key at startup)
    $aesLine = Select-String -Path $AnvilLog, $AnvilErrLog -Pattern "encoded AES key: (\S+)" | Select-Object -Last 1
    if (-not $aesLine) {
        Get-Content $AnvilLog, $AnvilErrLog -ErrorAction SilentlyContinue
        throw "Could not read AES_KEY from Anvil log"
    }
    $AesKey = $aesLine.Matches.Groups[1].Value
    if ($AesKey.Length -ne 43) { throw "Unexpected AES_KEY length $($AesKey.Length)" }

    # Operator auth (self-signed cert; PS 7 needs -SkipCertificateCheck)
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("forge:forge"))
    $auth = Invoke-WebRequest -Uri "https://127.0.0.1:${ConduitPort}/authenticate" `
        -Method POST -Headers @{ Authorization = "Basic $pair" } -UseBasicParsing -SkipCertificateCheck
    $OpToken = (Get-WebResponseText $auth).Trim()

    # Build implant via build_imp (registers UUID in DB)
    $buildHeaders = @{
        "X-Token"       = $OpToken
        "X-Target"      = "windows_stargate"
        "X-Format"      = "exe"
        "X-Target-IP"   = "127.0.0.1"
        "X-Target-Port" = "$ImplantPort"
        "X-TSleep"      = "2"
        "X-Jitter"      = "0"
    }
    $BeaconPath = Join-Path $WorkDir "beacon.exe"
    Invoke-WebRequest -Uri "https://127.0.0.1:${ConduitPort}/build_imp" `
        -Method POST -Headers $buildHeaders -OutFile $BeaconPath -UseBasicParsing -SkipCertificateCheck
    if ((Get-Item $BeaconPath).Length -lt 4096) { throw "beacon.exe too small" }

    # Run beacon (ignore TLS errors on implant channel too)
    $BeaconProc = Start-Process -FilePath $BeaconPath -PassThru
    Start-Sleep -Seconds 8

    $imps = Invoke-WebRequest -Uri "https://127.0.0.1:${ConduitPort}/imps" `
        -Headers @{ "X-Token" = $OpToken } -UseBasicParsing -SkipCertificateCheck
    $impsBody = Get-WebResponseText $imps
    Write-Host "imps response: $impsBody"
    if ($impsBody -notmatch "windows") {
        throw "Expected implant check-in on /imps; got: $impsBody"
    }

    Write-Host "PASS: win-stargate beacon checked in"
}
finally {
    Get-Process -Name "beacon","anvil" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Pop-Location
}
