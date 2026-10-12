param(
  [string]$ManifestPath = (Join-Path $PSScriptRoot '..\tools\manifest.json')
)

$ErrorActionPreference = 'Stop'
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

$builderRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$projectRoot = (Resolve-Path (Join-Path $builderRoot '..')).Path

function Get-Tool([string]$Name) {
  $tool = $manifest.tools | Where-Object { $_.name -eq $Name } | Select-Object -First 1
  if (-not $tool) { throw "$Name is missing from the tool manifest" }
  return $tool
}

function Assert-FileHash([string]$Path, [string]$Expected, [string]$Label) {
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
  if ($actual -ne $Expected) {
    throw "$Label hash mismatch: expected $Expected, got $actual"
  }
}

function Ensure-PayloadDumper {
  $tool = Get-Tool 'payload-dumper-go'
  $target = Join-Path $projectRoot $tool.executable_path
  $targetDir = Split-Path -Parent $target
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  if (Test-Path -LiteralPath $target) {
    Assert-FileHash $target $tool.executable_sha256 'payload-dumper-go executable'
    Write-Host "payload-dumper-go already verified: $target"
    return
  }

  $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('peridot-builder-payload-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
  try {
    $archive = Join-Path $tempRoot 'payload-dumper-go.tar.gz'
    Invoke-WebRequest -UseBasicParsing -Uri $tool.url -OutFile $archive -TimeoutSec 120
    Assert-FileHash $archive $tool.archive_sha256 'payload-dumper-go archive'

    tar -xzf $archive -C $tempRoot
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed with exit code $LASTEXITCODE" }

    $exe = Get-ChildItem -LiteralPath $tempRoot -Recurse -File |
      Where-Object { $_.Name -match '^payload-dumper-go.*\.exe$' } |
      Select-Object -First 1
    if (-not $exe) { throw 'payload-dumper-go executable not found in release archive' }

    Copy-Item -LiteralPath $exe.FullName -Destination $target
    Assert-FileHash $target $tool.executable_sha256 'payload-dumper-go executable'
    Write-Host "Installed verified payload-dumper-go $($tool.version): $target"
  } finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Ensure-Base64File([object]$Tool, [string]$HashField, [string]$Label) {
  if ($Tool.path) {
    $target = Join-Path $projectRoot $Tool.path
  } else {
    $target = Join-Path $projectRoot $Tool.executable_path
  }
  $targetDir = Split-Path -Parent $target
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  $expected = $Tool.$HashField
  if (Test-Path -LiteralPath $target) {
    Assert-FileHash $target $expected $Label
    Write-Host "$Label already verified: $target"
    return
  }

  $temp = Join-Path ([IO.Path]::GetTempPath()) ('peridot-tool-' + [guid]::NewGuid().ToString('N') + '.txt')
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $Tool.url -OutFile $temp -TimeoutSec 120
    $encoded = [IO.File]::ReadAllText($temp).Trim()
    [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($encoded))
    Assert-FileHash $target $expected $Label
    Write-Host "Installed verified $($Label): $target"
  } finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
  }
}

function Ensure-AvbTool {
  $tool = Get-Tool 'avbtool'
  $target = Join-Path $projectRoot $tool.executable_path
  $targetDir = Split-Path -Parent $target
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  if (Test-Path -LiteralPath $target) {
    Assert-FileHash $target $tool.executable_sha256 'avbtool'
    Write-Host "avbtool already verified: $target"
    return
  }

  Ensure-Base64File $tool 'executable_sha256' 'avbtool'
  $version = & python $target version
  if ($LASTEXITCODE -ne 0) { throw "avbtool version check failed with exit code $LASTEXITCODE" }
  Write-Host "Verified avbtool $($version): $target"
}

function Ensure-AvbTestKey {
  $tool = Get-Tool 'aosp-avb-testkey-rsa4096'
  Ensure-Base64File $tool 'sha256' 'AOSP AVB development test key'
}

Ensure-PayloadDumper
Ensure-AvbTool
Ensure-AvbTestKey
