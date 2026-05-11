# ffl-mcp installer for Windows
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/nuwainfo/ffl-mcp/refs/heads/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$RepoOwner = "nuwainfo"
$RepoName  = "ffl-mcp"

# -- Resolve latest release tag (no API: follow redirect) --------------------
Write-Host "Resolving latest release..."
$LatestUrl = "https://github.com/$RepoOwner/$RepoName/releases/latest"

$response = Invoke-WebRequest -Uri $LatestUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
$Tag = $response.Headers.Location -replace '.*/tag/', ''

if (-not $Tag) {
    # Some PS versions follow redirects automatically -- extract from final URL
    $response = Invoke-WebRequest -Uri $LatestUrl -UseBasicParsing
    $Tag = $response.BaseResponse.ResponseUri.AbsoluteUri -replace '.*/tag/', ''
}

if (-not $Tag) {
    Write-Error "Could not resolve latest release tag"
    exit 1
}
Write-Host "Latest tag: $Tag"

# -- Fetch asset list (no API: scrape expanded_assets HTML) ------------------
$AssetsUrl  = "https://github.com/$RepoOwner/$RepoName/releases/expanded_assets/$Tag"
$AssetsHtml = (Invoke-WebRequest -Uri $AssetsUrl -UseBasicParsing).Content

$Pattern     = "/$RepoOwner/$RepoName/releases/download/$Tag/[^`"'><\s]+"
$AssetPaths  = [regex]::Matches($AssetsHtml, $Pattern) | ForEach-Object { $_.Value } | Select-Object -Unique
$AssetUrls   = $AssetPaths | ForEach-Object { "https://github.com$_" }
$AssetNames  = $AssetUrls  | ForEach-Object { ($_ -split '/')[-1] }

# -- Find ffl-mcp.exe (raw binary, not the NSIS setup installer) --------------
$ExeUrl = $AssetUrls | Where-Object { ($_ -split '/')[-1] -eq "ffl-mcp.exe" } | Select-Object -First 1

# -- Install ------------------------------------------------------------------
if ($ExeUrl) {
    Write-Host "Found binary: $ExeUrl"
    $TmpExe = Join-Path $env:TEMP "ffl-mcp-installer-tmp.exe"
    Write-Host "Downloading..."
    Invoke-WebRequest -Uri $ExeUrl -OutFile $TmpExe -UseBasicParsing
    Write-Host "Registering MCP server with Claude and Codex..."
    & $TmpExe install
    Remove-Item $TmpExe -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "No Windows binary found in release $Tag -- falling back to uvx."
    Write-Host "Available assets:"; $AssetNames | ForEach-Object { Write-Host "  - $_" }

    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        Write-Host "uv not found. Installing uv..."
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    }

    uvx --from "git+https://github.com/$RepoOwner/$RepoName" ffl-mcp install
}

Write-Host ""
Write-Host "Done! Restart Claude/Codex to connect the ffl-mcp server."
