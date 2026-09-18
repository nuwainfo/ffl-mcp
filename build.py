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
import tempfile
import tomllib
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


def _readDependency(packageName: str) -> str:
    projectPath = Path(__file__).parent / "pyproject.toml"
    projectData = tomllib.loads(projectPath.read_text(encoding="utf-8"))
    dependencies = projectData["project"]["dependencies"]
    for dependency in dependencies:
        if dependency.lower().startswith(packageName.lower()):
            return dependency
    raise RuntimeError(f"Missing project dependency: {packageName}")


FAST_MCP_REQUIREMENT = _readDependency("fastmcp")
COMTYPES_REQUIREMENT = _readDependency("comtypes")

# ── Paths ─────────────────────────────────────────────────────────────────────
PYAPP_REPO_ZIP = "https://github.com/ofek/pyapp/archive/refs/heads/master.zip"
PYAPP_DIR = Path("pyapp-src")
DIST_DIR = Path("dist")
BUILD_CACHE_DIR = Path("build-cache")
EXEC_SPEC = "src.Entrypoint:main"
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
    # Must use --wheel to build directly from source tree.
    # Build directly from the source tree so the standalone package contains
    # the MCP server and its ffl-python dependency metadata.
    run(["uv", "build", "--wheel", "--out-dir", str(DIST_DIR)])


def validateWheel(wheelPath: Path) -> None:
    import zipfile
    with zipfile.ZipFile(wheelPath) as zf:
        names = zf.namelist()
    if not any(n.endswith(".py") for n in names):
        print(
            f"ERROR: wheel {wheelPath.name} contains no .py files.\n"
            "This happens when the wheel was built via `uv build` (sdist→wheel path)\n"
            "instead of `uv build --wheel`. Delete the wheel and re-run without --skip-wheel.",
            file=sys.stderr,
        )
        sys.exit(1)


def findWheel() -> Path:
    wheels = sorted(DIST_DIR.glob("ffl_mcp-*.whl"))
    if not wheels:
        wheels = sorted(DIST_DIR.glob("ffl-mcp-*.whl"))
    if not wheels:
        print("ERROR: no ffl-mcp wheel found in dist/. Run without --skip-wheel.", file=sys.stderr)
        sys.exit(1)
    wheel = max(wheels, key=lambda p: p.stat().st_mtime)
    validateWheel(wheel)
    return wheel


# ── Step 2: Pre-installed Python distribution ─────────────────────────────────

# Top-level site-packages entries confirmed unused by any ffl-mcp code path — see
# "Why is the final exe so large?" investigation. fastmcp/mcp pull in a large
# transitive dependency graph (OAuth via Authlib/joserfc, a Redis-backed task queue,
# OpenAPI-to-tool conversion, the `fastmcp` CLI's own framework, rich's optional
# renderers, keyring, etc.) that ffl-mcp's stdio tool-serving usage never touches.
#
# Verified safe by, in order:
#   1. A broad in-process exercise calling every @mcp.tool directly + starting the
#      http/sse transports and sending real requests, diffing sys.modules before/after.
#   2. Removing the resulting candidates and running the full `tests/*Test.py` suite
#      against the pruned interpreter.
#   3. Calling every @mcp.tool over a REAL stdio JSON-RPC session (not direct function
#      calls) — this is what caught that fastmcp's per-request state store needs
#      `cachetools`, and that `mcp`'s stdio transport needs pywin32's `pywintypes`/
#      `pythoncom` on Windows via a `.pth`-activated `win32/lib` path, both of which
#      are intentionally NOT in this list (do not add them back without re-breaking
#      that same test).
# Re-run steps 2 and 3 before adding anything new here — a package can be "never
# imported" in a quick check yet still be needed by a specific request-handling path
# (e.g. the state store) that only triggers on a real tool call.
PRUNE_FROM_ARCHIVE = {
    "PyWin32.chm",
    "README.txt",
    "_yaml",
    "adodbapi",
    "aiofile",
    "annotated_doc",
    "attr",
    "attrs",
    "authlib",
    "burner_redis",
    "caio",
    "certifi",
    "colorama",
    "cyclopts",
    "diskcache",
    "dns",
    "docstring_parser",
    "docutils",
    "email_validator",
    "fakeredis",
    "httpcore",
    "httpcore2",
    "httpx",
    "httpx_sse",
    "isapi",
    "jaraco",
    "joserfc",
    "jsonref.py",
    "jsonschema",
    "jsonschema_path",
    "jsonschema_specifications",
    "jwt",
    "keyring",
    "lupa",
    "markdown_it",
    "mdurl",
    "more_itertools",
    "multipart",
    "openapi_pydantic",
    "pathable",
    "pathvalidate",
    "pip",
    "prometheus_client",
    "proxytypes.py",
    "pygments",
    "pyperclip",
    "pythonjsonlogger",
    "pythonwin",
    "pywin32.version.txt",
    "referencing",
    "rich_rst",
    "rpds",
    "shellingham",
    "sortedcontainers",
    "truststore",
    "typer",
    "win32com",
    "win32comext",
    "win32ctypes",
    "yaml",
}


def buildArchiveFilter():
    """
    tarfile filter that drops PRUNE_FROM_ARCHIVE entries from the archived copy only.

    Pruning is applied here (at archive time) rather than by deleting from
    PYTHON_DIST_DIR directly, because that directory is reused as pip's install
    target across builds/`--rebuild-dist` runs — deleting `pip` or other packages
    from it directly would break the next `pip install` into the same directory.
    """
    def _filter(tarinfo: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
        parts = tarinfo.name.split("/")
        if len(parts) >= 4 and parts[0] == "python" and parts[1] == "Lib" and parts[2] == "site-packages":
            if parts[3] in PRUNE_FROM_ARCHIVE:
                return None
        return tarinfo

    return _filter



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

    fflPythonSource = os.environ.get("FFL_PYTHON_SOURCE")
    if fflPythonSource:
        sourcePath = Path(fflPythonSource).resolve()
        if not (sourcePath / "pyproject.toml").is_file():
            raise RuntimeError(f"FFL_PYTHON_SOURCE is not an ffl-python project: {sourcePath}")
        print(f"  Pre-installing local ffl-python from {sourcePath}...")
        run([
            str(pythonExe), "-m", "pip", "install", str(sourcePath),
            "--no-deps", "--force-reinstall", "--quiet",
        ])
        run([
            str(pythonExe), "-m", "pip", "install", FAST_MCP_REQUIREMENT, COMTYPES_REQUIREMENT,
            "--quiet",
        ])

    print(f"  Pre-installing {wheelPath.name} and all dependencies into distribution...")
    installCommand = [
        str(pythonExe), "-m", "pip", "install",
        str(wheelPath.resolve()),
        "--force-reinstall",
        "--no-warn-script-location",
        "--quiet",
    ]
    if fflPythonSource:
        installCommand.append("--no-deps")
    run(installCommand)
    run([
        str(pythonExe), "-c",
        "from fastmcp import FastMCP; import src.Entrypoint",
    ])
    print("  Packages installed.")

    print("  Archiving distribution with pre-installed packages (pruning unused deps)...")
    with tarfile.open(PYTHON_PREINSTALLED_ARCHIVE, "w:gz") as tar:
        tar.add(PYTHON_DIST_DIR / "python", arcname="python", filter=buildArchiveFilter())

    sizeMb = PYTHON_PREINSTALLED_ARCHIVE.stat().st_size / 1_048_576
    print(f"  Pre-installed distribution archived: {PYTHON_PREINSTALLED_ARCHIVE} ({sizeMb:.0f} MB)")

    verifyPrunedDistribution()


def verifyPrunedDistribution() -> None:
    """
    Extract the just-built archive and run the real test suite against it, using the
    current repo's tests/src (not whatever got pip-installed into the archive) so this
    catches PRUNE_FROM_ARCHIVE entries that turn out to be needed by the current code.
    This is not a substitute for the real-stdio-transport check described above
    PRUNE_FROM_ARCHIVE (that one requires a real network round trip and isn't worth
    running on every build) but it does catch the more common "this package is
    actually imported somewhere" regression automatically.
    """
    print("  Verifying pruned distribution against the test suite...")
    with tempfile.TemporaryDirectory(prefix="ffl-mcp-verify-") as tmpDir:
        with tarfile.open(PYTHON_PREINSTALLED_ARCHIVE, "r:gz") as tar:
            tar.extractall(tmpDir, filter="data")
        verifyPython = Path(tmpDir) / "python" / "python.exe"
        run([str(verifyPython), "-m", "unittest", "discover", "-s", "tests", "-p", "*Test.py"])
    print("  Pruned distribution passes the test suite.")


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
    """Generate the NSIS helper that delegates registration to the app backend."""
    lines = [
        "# Auto-generated by build.py",
        "param([string]$InstallDir)",
        "$ErrorActionPreference = 'Stop'",
        "",
        "$binaryPath = Join-Path $InstallDir 'ffl-mcp.exe'",
        "",
        "$installedVersion = & $binaryPath --version",
        f"if ($LASTEXITCODE -ne 0 -or $installedVersion -ne '{APP_VERSION}') {{",
        f"    throw \"Expected ffl-mcp {APP_VERSION}, got $installedVersion. Close MCP clients and retry.\"",
        "}",
        "",
        "& $binaryPath install --target all --overwrite",
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
    ]
    return "\n".join(lines) + "\n"


def generateUninstallScript() -> str:
    """Generate the NSIS helper that delegates removal to the app backend."""
    lines = [
        "# Auto-generated by build.py",
        "$ErrorActionPreference = 'Stop'",
        "",
        "$binaryPath = Join-Path $PSScriptRoot 'ffl-mcp.exe'",
        "& $binaryPath uninstall --target all",
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
    ]
    return "\n".join(lines) + "\n"


def writeHelperScripts():
    BUILD_CACHE_DIR.mkdir(exist_ok=True)
    INSTALL_SCRIPT.write_text(generateInstallScript(), encoding="utf-8")
    UNINSTALL_SCRIPT.write_text(generateUninstallScript(), encoding="utf-8")


def buildInstaller(exePath: Path) -> Optional[Path]:
    """Build a Windows installer from scripts/Installer.nsi using NSIS."""
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

    nsiScript = Path("scripts") / "Installer.nsi"
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
    os.chdir(Path(__file__).resolve().parent)
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
