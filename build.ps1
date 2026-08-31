# Builds warp-chain into ./build. Usage:
#   .\build.ps1              # current platform (windows amd64)
#   .\build.ps1 win,android  # one or more of: win, linux, arm64, android
param(
    [string]$Targets = "win"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path build | Out-Null

# git tag wins, fall back to short hash, then "dev". git describe writes to
# stderr when there are no tags, which PowerShell promotes to a terminating
# error under Stop — so drop EAP for the duration of the call.
$ErrorActionPreference = "Continue"
$Version = git describe --tags --always --dirty 2>$null
$ErrorActionPreference = "Stop"
if (-not $Version) { $Version = "dev" }
Write-Host "version: $Version"

function Build($os, $arch, $ext) {
    $out = "build/warp-chain-$os-$arch$ext"
    $env:GOOS = $os
    $env:GOARCH = $arch
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $out .
    if ($LASTEXITCODE -ne 0) { throw "build failed: $out" }
    Write-Host "OK  $out"
}

foreach ($t in $Targets.Split(",")) {
    switch ($t.Trim()) {
        "win"     { Build windows amd64 ".exe" }
        "linux"   { Build linux   amd64 ""     }
        "arm64"   { Build linux   arm64 ""     }
        "android" { Build android arm64 ""     }
        default   { Write-Error "unknown target '$t' - use win, linux, arm64, android" }
    }
}
