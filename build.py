#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Build ffl-mcp: PyApp binary + Windows installer (NSIS MUI2).

Usage:
    python build.py                  # full build (binary + installer)
    python build.py --skip-wheel     # reuse existing wheel in dist/
    python build.py --rebuild-dist   # force re-install packages into distribution
    python build.py --skip-installer # skip NSIS installer step
    python build.py --installer-only # only build installer, reuse dist/ffl-mcp.exe
    python build.py --clean          # remove all build artifacts

Outputs:
    dist/ffl-mcp.exe           standalone binary (no Python/uv required)
    dist/ffl-mcp-setup.exe     Windows installer for coworkers

Installer behaviour (NSIS + MUI2):
  - Installs ffl-mcp.exe to %LocalAppData%\\Programs\\ffl-mcp\\
  - Registers the MCP server directly via PowerShell (no PyApp extraction during
    install — avoids hang).  PyApp extraction happens on first actual use.
  - Provides an uninstaller (Add/Remove Programs) that removes the binary, removes
    the MCP server entry from Claude Desktop config and Claude Code CLI, and cleans
    the PyApp extraction cache.

How the binary is built:
  1. Build a wheel with `uv build`.
  2. Download Python 3.12 astral-sh distribution (cached in build-cache/).
  3. Pre-install the wheel + all deps into the distribution.
  4. Compile PyApp with PYAPP_FULL_ISOLATION=1 + PYAPP_SKIP_INSTALL=1 so the binary
     just extracts the pre-built Python+packages on first run — no pip, no network.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

# ── Application metadata ──────────────────────────────────────────────────────
def _readVersion() -> str:
    toml = Path(__file__).parent / "pyproject.toml"
    match = re.search(r'^version\s*=\s*"([^"]+)"', toml.read_text(), re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find version in pyproject.toml")
    return match.group(1)

APP_VERSION = _readVersion()
APP_NAME = "FastFileLink MCP"
APP_PUBLISHER = "FastFileLink"
APP_URL = "https://fastfilelink.com"
MCP_SERVER_NAME = "ffl"

# ── Paths ─────────────────────────────────────────────────────────────────────
PYAPP_REPO_ZIP = "https://github.com/ofek/pyapp/archive/refs/heads/master.zip"
PYAPP_DIR = Path("pyapp-src")
DIST_DIR = Path("dist")
BUILD_CACHE_DIR = Path("build-cache")
EXEC_SPEC = "src.entrypoint:main"
PYTHON_VERSION = "3.12"

# Python 3.12.12 Windows x64 install_only_stripped (astral-sh build).
PYTHON_DIST_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/"
    "cpython-3.12.12%2B20251014-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
)
DIST_PYTHON_PATH = "python/python.exe"
DIST_SITE_PACKAGES = "python/Lib/site-packages"

PYTHON_DIST_ARCHIVE = BUILD_CACHE_DIR / "python-dist.tar.gz"
PYTHON_DIST_DIR = BUILD_CACHE_DIR / "python-dist"
PYTHON_PREINSTALLED_ARCHIVE = BUILD_CACHE_DIR / "python-preinstalled.tar.gz"
INSTALL_SCRIPT = BUILD_CACHE_DIR / "install-mcp.ps1"
UNINSTALL_SCRIPT = BUILD_CACHE_DIR / "uninstall-mcp.ps1"


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, **kwargs):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, check=True, **kwargs)
    return result


# ── Step 1: Wheel ─────────────────────────────────────────────────────────────

def buildWheel():
    print("\n[1/6] Building wheel...")
    DIST_DIR.mkdir(exist_ok=True)
    run(["uv", "build", "--wheel", "--out-dir", str(DIST_DIR)])


def findWheel() -> Path:
    wheels = sorted(DIST_DIR.glob("ffl_mcp-*.whl"))
    if not wheels:
        wheels = sorted(DIST_DIR.glob("ffl-mcp-*.whl"))
    if not wheels:
        print("ERROR: no ffl-mcp wheel found in dist/. Run without --skip-wheel.", file=sys.stderr)
        sys.exit(1)
    return max(wheels, key=lambda p: p.stat().st_mtime)


# ── Step 2: Pre-installed Python distribution ─────────────────────────────────

def downloadPythonDist():
    BUILD_CACHE_DIR.mkdir(exist_ok=True)
    if PYTHON_DIST_ARCHIVE.exists():
        print(f"  Using cached Python distribution: {PYTHON_DIST_ARCHIVE}")
        return
    print("  Downloading Python 3.12 distribution (~25 MB)...")

    def _progress(count, blockSize, totalSize):
        if totalSize > 0:
            pct = min(100, count * blockSize * 100 // totalSize)
            print(f"\r    {pct}%", end="", flush=True)

    urllib.request.urlretrieve(PYTHON_DIST_URL, PYTHON_DIST_ARCHIVE, _progress)
    print(f"\r  Downloaded: {PYTHON_DIST_ARCHIVE} ({PYTHON_DIST_ARCHIVE.stat().st_size // 1_048_576} MB)")


def extractPythonDist():
    if PYTHON_DIST_DIR.exists():
        print(f"  Using cached extracted distribution: {PYTHON_DIST_DIR}")
        return
    print("  Extracting Python distribution...")
    PYTHON_DIST_DIR.mkdir(parents=True)
    with tarfile.open(PYTHON_DIST_ARCHIVE, "r:gz") as tar:
        tar.extractall(PYTHON_DIST_DIR, filter="data")
    print(f"  Extracted to {PYTHON_DIST_DIR}")


def prepareDistribution(wheelPath: Path, rebuildDist: bool):
    """Pre-install wheel + deps into the Python distribution and archive for PyApp embedding."""
    print("\n[2/6] Preparing pre-bundled Python distribution...")

    if PYTHON_PREINSTALLED_ARCHIVE.exists() and not rebuildDist:
        sizeMb = PYTHON_PREINSTALLED_ARCHIVE.stat().st_size / 1_048_576
        print(f"  Using cached pre-installed distribution: {PYTHON_PREINSTALLED_ARCHIVE} ({sizeMb:.0f} MB)")
        print("  (Pass --rebuild-dist to force reinstall of packages)")
        return

    downloadPythonDist()
    extractPythonDist()

    pythonExe = PYTHON_DIST_DIR / "python" / "python.exe"
    if not pythonExe.exists():
        print(f"ERROR: Python executable not found at {pythonExe}", file=sys.stderr)
        sys.exit(1)

    print(f"  Pre-installing {wheelPath.name} and all dependencies into distribution...")
    run([
        str(pythonExe), "-m", "pip", "install",
        str(wheelPath.resolve()),
        "--no-warn-script-location",
        "--quiet",
    ])
    print("  Packages installed.")

    print("  Archiving distribution with pre-installed packages...")
    with tarfile.open(PYTHON_PREINSTALLED_ARCHIVE, "w:gz") as tar:
        tar.add(PYTHON_DIST_DIR / "python", arcname="python")

    sizeMb = PYTHON_PREINSTALLED_ARCHIVE.stat().st_size / 1_048_576
    print(f"  Pre-installed distribution archived: {PYTHON_PREINSTALLED_ARCHIVE} ({sizeMb:.0f} MB)")


# ── Steps 3 & 4: PyApp binary ─────────────────────────────────────────────────

def downloadPyappSource():
    zipPath = Path("pyapp-master.zip")
    print("Downloading PyApp source from GitHub...")
    urllib.request.urlretrieve(PYAPP_REPO_ZIP, zipPath)
    with zipfile.ZipFile(zipPath) as zf:
        zf.extractall(".")
    extracted = Path("pyapp-master")
    if PYAPP_DIR.exists():
        shutil.rmtree(PYAPP_DIR)
    extracted.rename(PYAPP_DIR)
    zipPath.unlink()
    print(f"PyApp source extracted to {PYAPP_DIR}/")


def buildPyapp() -> Path:
    print("\n[3/6] Ensuring PyApp source is available...")
    if not PYAPP_DIR.exists():
        downloadPyappSource()
    else:
        print(f"  Using cached {PYAPP_DIR}/")

    print("\n[4/6] Compiling PyApp with cargo...")
    env = os.environ.copy()
    env["PYAPP_PROJECT_NAME"] = "ffl-mcp"
    env["PYAPP_PROJECT_VERSION"] = APP_VERSION
    env["PYAPP_EXEC_SPEC"] = EXEC_SPEC
    env["PYAPP_PYTHON_VERSION"] = PYTHON_VERSION
    # PYAPP_DISTRIBUTION_PATH copies the local archive into the binary at compile time.
    # Do NOT set PYAPP_DISTRIBUTION_SOURCE alongside it — build.rs panics if both are set.
    env["PYAPP_FULL_ISOLATION"] = "1"
    env["PYAPP_SKIP_INSTALL"] = "1"
    env["PYAPP_DISTRIBUTION_PATH"] = str(PYTHON_PREINSTALLED_ARCHIVE.resolve())
    env["PYAPP_DISTRIBUTION_FORMAT"] = "tar|gzip"
    env["PYAPP_DISTRIBUTION_PYTHON_PATH"] = DIST_PYTHON_PATH
    env["PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH"] = DIST_SITE_PACKAGES
    env["PYAPP_SKIP_COMPRESSION"] = "true"
    # Makes PyApp set PYAPP env var to the binary's own path so install.py can
    # register the correct command path in Claude configs.
    env["PYAPP_PASS_LOCATION"] = "1"

    run(["cargo", "build", "--release"], cwd=PYAPP_DIR, env=env)

    isWindows = platform.system() == "Windows"
    builtBinary = PYAPP_DIR / "target" / "release" / ("pyapp.exe" if isWindows else "pyapp")
    if not builtBinary.exists():
        print(f"ERROR: expected compiled binary at {builtBinary}", file=sys.stderr)
        sys.exit(1)
    return builtBinary


def copyOutput(builtBinary: Path) -> Path:
    print("\n[5/6] Copying output binary...")
    DIST_DIR.mkdir(exist_ok=True)
    isWindows = platform.system() == "Windows"
    outputName = "ffl-mcp.exe" if isWindows else "ffl-mcp"
    outputPath = DIST_DIR / outputName
    shutil.copy2(builtBinary, outputPath)
    outputPath.chmod(outputPath.stat().st_mode | 0o111)
    print(f"  Binary: {outputPath.resolve()} ({outputPath.stat().st_size / 1_048_576:.1f} MB)")
    return outputPath


# ── Step 6: Windows installer (NSIS + MUI2) ───────────────────────────────────

def findNsis() -> Optional[Path]:
    candidates = [
        shutil.which("makensis"),
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
    ]
    for c in candidates:
        if c and Path(c).exists():
            return Path(c)
    return None


def generateInstallScript() -> str:
    """PowerShell script run at install time.

    Registers ffl-mcp directly in Claude Desktop JSON config, Codex config,
    Claude Code CLI, and Codex CLI
    without invoking ffl-mcp.exe, so there is no PyApp extraction hang during install.
    PyApp extraction happens on first actual use of the MCP server instead.
    """
    # Note: single-quoted PS strings don't expand variables, so we use them for
    # literal path fragments. Double-quoted strings expand $binaryPath etc.
    lines = [
        "# Auto-generated by build.py",
        "param([string]$InstallDir)",
        "$ErrorActionPreference = 'SilentlyContinue'",
        "",
        "$binaryPath = Join-Path $InstallDir 'ffl-mcp.exe'",
        "",
        "# 1. Claude Desktop config",
        "$configPath = Join-Path $env:APPDATA 'Claude\\claude_desktop_config.json'",
        "try {",
        "    if (Test-Path $configPath) {",
        "        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json",
        "    } else {",
        "        $cfg = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }",
        "    }",
        "    if ($null -eq $cfg.mcpServers) {",
        "        $cfg | Add-Member -NotePropertyName mcpServers -NotePropertyValue ([PSCustomObject]@{}) -Force",
        "    }",
        "    $entry = [PSCustomObject]@{ command = $binaryPath; args = @() }",
        f"    $cfg.mcpServers | Add-Member -NotePropertyName {MCP_SERVER_NAME} -NotePropertyValue $entry -Force",
        "    $parent = Split-Path $configPath -Parent",
        "    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }",
        "    $utf8NoBom = New-Object System.Text.UTF8Encoding $false",
        "    [System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 20), $utf8NoBom)",
        "} catch {}",
        "",
        "# 2. Codex config (shared by Codex Desktop/CLI/IDE)",
        "try {",
        "    $codexConfigPath = Join-Path $env:USERPROFILE '.codex\\config.toml'",
        "    $tomlBinaryPath = $binaryPath.Replace('\\', '\\\\').Replace('\"', '\\\"')",
        f"    $serverToml = \"`n[mcp_servers.{MCP_SERVER_NAME}]`ncommand = `\"$tomlBinaryPath`\"`nargs = []`n\"",
        "    if (Test-Path $codexConfigPath) {",
        "        $codexConfig = Get-Content $codexConfigPath -Raw",
        "    } else {",
        "        $codexConfig = ''",
        "    }",
        f"    $pattern = '(?ms)^\\[mcp_servers\\.{MCP_SERVER_NAME}(?:\\.[^\\]]+)?\\]\\r?\\n.*?(?=^\\[|\\z)'",
        "    $codexConfig = [regex]::Replace($codexConfig, $pattern, '').TrimEnd()",
        "    if ($codexConfig.Length -gt 0) { $codexConfig = $codexConfig + \"`n`n\" + $serverToml } else { $codexConfig = $serverToml.TrimStart() }",
        "    $parent = Split-Path $codexConfigPath -Parent",
        "    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }",
        "    $utf8NoBom = New-Object System.Text.UTF8Encoding $false",
        "    [System.IO.File]::WriteAllText($codexConfigPath, $codexConfig, $utf8NoBom)",
        "} catch {}",
        "",
        "# 3. Claude Code CLI (best-effort)",
        "try {",
        "    $entry = [PSCustomObject]@{ command = $binaryPath; args = @() }",
        "    $entryJson = $entry | ConvertTo-Json -Compress",
        f"    & claude mcp remove -s user {MCP_SERVER_NAME} 2>&1 | Out-Null",
        f"    & claude mcp add-json -s user {MCP_SERVER_NAME} $entryJson 2>&1 | Out-Null",
        "} catch {}",
        "",
        "# 4. Codex CLI (best-effort)",
        "try {",
        f"    & codex mcp remove {MCP_SERVER_NAME} 2>&1 | Out-Null",
        f"    & codex mcp add {MCP_SERVER_NAME} -- $binaryPath 2>&1 | Out-Null",
        "} catch {}",
        "",
        "# 5. Warm PyApp cache so MCP clients do not trigger first-run extraction concurrently",
        "try { & $binaryPath --help 2>&1 | Out-Null } catch {}",
    ]
    return "\n".join(lines) + "\n"


def generateUninstallScript() -> str:
    """PowerShell script run at uninstall time."""
    lines = [
        "# Auto-generated by build.py",
        "$ErrorActionPreference = 'SilentlyContinue'",
        "",
        "# 1. Claude Desktop config",
        "$configPath = Join-Path $env:APPDATA 'Claude\\claude_desktop_config.json'",
        "if (Test-Path $configPath) {",
        "    try {",
        "        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json",
        f"        $cfg.mcpServers.PSObject.Properties.Remove('{MCP_SERVER_NAME}')",
        "        $utf8NoBom = New-Object System.Text.UTF8Encoding $false",
        "        [System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 20), $utf8NoBom)",
        "    } catch {}",
        "}",
        "",
        "# 2. Codex config",
        "$codexConfigPath = Join-Path $env:USERPROFILE '.codex\\config.toml'",
        "if (Test-Path $codexConfigPath) {",
        "    try {",
        "        $codexConfig = Get-Content $codexConfigPath -Raw",
        f"        $pattern = '(?ms)^\\[mcp_servers\\.{MCP_SERVER_NAME}(?:\\.[^\\]]+)?\\]\\r?\\n.*?(?=^\\[|\\z)'",
        "        $codexConfig = [regex]::Replace($codexConfig, $pattern, '').TrimEnd() + \"`n\"",
        "        $utf8NoBom = New-Object System.Text.UTF8Encoding $false",
        "        [System.IO.File]::WriteAllText($codexConfigPath, $codexConfig, $utf8NoBom)",
        "    } catch {}",
        "}",
        "",
        "# 3. Claude Code CLI (best-effort)",
        f"try {{ & claude mcp remove -s user {MCP_SERVER_NAME} 2>&1 | Out-Null }} catch {{}}",
        "",
        "# 4. Codex CLI (best-effort)",
        f"try {{ & codex mcp remove {MCP_SERVER_NAME} 2>&1 | Out-Null }} catch {{}}",
    ]
    return "\n".join(lines) + "\n"


def writeHelperScripts():
    BUILD_CACHE_DIR.mkdir(exist_ok=True)
    INSTALL_SCRIPT.write_text(generateInstallScript(), encoding="utf-8")
    UNINSTALL_SCRIPT.write_text(generateUninstallScript(), encoding="utf-8")


def buildInstaller(exePath: Path) -> Optional[Path]:
    """Build a Windows installer from installer.nsi using NSIS."""
    print("\n[6/6] Building Windows installer...")

    if platform.system() != "Windows":
        print("  Skipping — installer is only built on Windows.")
        return None

    nsisPath = findNsis()
    if nsisPath is None:
        print("  WARNING: makensis not found.")
        print("  Install NSIS from: https://nsis.sourceforge.io/Download")
        print("  Then re-run:  python build.py --installer-only")
        return None

    nsiScript = Path("installer.nsi")
    if not nsiScript.exists():
        print(f"  ERROR: {nsiScript} not found.", file=sys.stderr)
        return None

    print(f"  Using NSIS: {nsisPath}")

    DIST_DIR.mkdir(exist_ok=True)
    writeHelperScripts()

    run([
        str(nsisPath),
        f"/DAPP_VERSION={APP_VERSION}",
        f"/DEXE_PATH={exePath.resolve()}",
        f"/DINSTALL_SCRIPT_PATH={INSTALL_SCRIPT.resolve()}",
        f"/DUNINSTALL_SCRIPT_PATH={UNINSTALL_SCRIPT.resolve()}",
        f"/DOUTPUT_DIR={DIST_DIR.resolve()}",
        str(nsiScript),
    ])

    setupExe = DIST_DIR / "ffl-mcp-setup.exe"
    if not setupExe.exists():
        print(f"  ERROR: expected installer at {setupExe}", file=sys.stderr)
        return None

    print(f"  Installer: {setupExe.resolve()} ({setupExe.stat().st_size / 1_048_576:.1f} MB)")
    return setupExe


# ── Clean ─────────────────────────────────────────────────────────────────────

def clean():
    print("Cleaning build artifacts...")
    for target in [PYAPP_DIR, DIST_DIR, BUILD_CACHE_DIR, Path("pyapp-master.zip")]:
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            print(f"  Removed {target}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build ffl-mcp binary and Windows installer")
    parser.add_argument("--clean", action="store_true", help="Remove build artifacts and exit")
    parser.add_argument("--skip-wheel", action="store_true", help="Reuse existing dist/*.whl")
    parser.add_argument("--skip-download", action="store_true", help="Require pyapp-src/ to already exist")
    parser.add_argument("--rebuild-dist", action="store_true", help="Force reinstall of packages into distribution")
    parser.add_argument("--skip-installer", action="store_true", help="Skip Windows installer step")
    parser.add_argument("--installer-only", action="store_true", help="Only build installer using existing dist/ffl-mcp.exe")
    args = parser.parse_args()

    if args.clean:
        clean()
        return

    if args.skip_download and not PYAPP_DIR.exists():
        print(f"ERROR: --skip-download requires {PYAPP_DIR}/ to exist", file=sys.stderr)
        sys.exit(1)

    if args.installer_only:
        exePath = DIST_DIR / "ffl-mcp.exe"
        if not exePath.exists():
            print(f"ERROR: --installer-only requires {exePath} to exist", file=sys.stderr)
            sys.exit(1)
        buildInstaller(exePath)
        return

    if not args.skip_wheel:
        if args.rebuild_dist:
            for oldWheel in DIST_DIR.glob("ffl_mcp-*.whl"):
                oldWheel.unlink()
                print(f"  Removed stale wheel: {oldWheel}")
        buildWheel()

    wheelPath = findWheel()
    print(f"  Using wheel: {wheelPath}")

    prepareDistribution(wheelPath, args.rebuild_dist)
    builtBinary = buildPyapp()
    exePath = copyOutput(builtBinary)

    if not args.skip_installer:
        buildInstaller(exePath)

    print("\nDone!")
    print(f"  Binary:    {(DIST_DIR / 'ffl-mcp.exe').resolve()}")
    setupExe = DIST_DIR / "ffl-mcp-setup.exe"
    if setupExe.exists():
        print(f"  Installer: {setupExe.resolve()}")


if __name__ == "__main__":
    main()
