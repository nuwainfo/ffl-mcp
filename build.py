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

"""Build a self-contained ffl-mcp executable using PyApp with all packages pre-bundled.

Usage:
    python build.py              # build for current platform
    python build.py --clean      # remove build artifacts first
    python build.py --skip-wheel # reuse existing wheel in dist/
    python build.py --rebuild-dist  # force re-install packages into distribution

Output: dist/ffl-mcp[.exe]

How it works:
  1. Build a wheel from the local source with `uv build`.
  2. Download Python 3.12 distribution (cached in build-cache/).
  3. Pre-install the wheel + all its dependencies into the distribution.
  4. Re-archive the distribution → write to pyapp-src/src/embed/distribution.
  5. Download / update the PyApp source from GitHub (or reuse cached copy).
  6. Set PYAPP_FULL_ISOLATION=1 + PYAPP_SKIP_INSTALL=1 so PyApp just extracts the
     pre-built distribution and runs immediately — no pip, no network on first launch.
  7. Compile PyApp with `cargo build --release`.
  8. Copy the resulting binary to dist/ffl-mcp[.exe].
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

PYAPP_REPO_ZIP = "https://github.com/ofek/pyapp/archive/refs/heads/master.zip"
PYAPP_DIR = Path("pyapp-src")
DIST_DIR = Path("dist")
BUILD_CACHE_DIR = Path("build-cache")
EXEC_SPEC = "src.entrypoint:main"
PYTHON_VERSION = "3.12"

# Python 3.12.12 Windows x64 install_only_stripped distribution (astral-sh build).
# This is the same distribution PyApp would download for Python 3.12 on Windows x64.
PYTHON_DIST_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/20251014/"
    "cpython-3.12.12%2B20251014-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
)
# Paths within the distribution archive
DIST_PYTHON_PATH = "python/python.exe"          # used by PYAPP_DISTRIBUTION_PYTHON_PATH
DIST_SITE_PACKAGES = "python/Lib/site-packages"  # used by PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH

PYTHON_DIST_ARCHIVE = BUILD_CACHE_DIR / "python-dist.tar.gz"
PYTHON_DIST_DIR = BUILD_CACHE_DIR / "python-dist"
PYTHON_PREINSTALLED_ARCHIVE = BUILD_CACHE_DIR / "python-preinstalled.tar.gz"


def run(cmd, **kwargs):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, check=True, **kwargs)
    return result


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


def buildWheel():
    print("\n[1/5] Building wheel...")
    DIST_DIR.mkdir(exist_ok=True)
    run(["uv", "build", "--wheel", "--out-dir", str(DIST_DIR)])


def findWheel():
    wheels = sorted(DIST_DIR.glob("ffl_mcp-*.whl"))
    if not wheels:
        wheels = sorted(DIST_DIR.glob("ffl-mcp-*.whl"))
    if not wheels:
        print("ERROR: no ffl-mcp wheel found in dist/. Run without --skip-wheel.", file=sys.stderr)
        sys.exit(1)
    return max(wheels, key=lambda p: p.stat().st_mtime)


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
        tar.extractall(PYTHON_DIST_DIR)
    print(f"  Extracted to {PYTHON_DIST_DIR}")


def prepareDistribution(wheelPath: Path, rebuildDist: bool):
    """Pre-install wheel + deps into the Python distribution and archive for PyApp embedding."""
    print("\n[2/5] Preparing pre-bundled Python distribution...")

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


def buildPyapp() -> Path:
    print("\n[3/5] Ensuring PyApp source is available...")
    if not PYAPP_DIR.exists():
        downloadPyappSource()
    else:
        print(f"  Using cached {PYAPP_DIR}/")

    print("\n[4/5] Compiling PyApp with cargo...")
    env = os.environ.copy()
    env["PYAPP_PROJECT_NAME"] = "ffl-mcp"
    env["PYAPP_PROJECT_VERSION"] = "0.1.5"
    env["PYAPP_EXEC_SPEC"] = EXEC_SPEC
    env["PYAPP_PYTHON_VERSION"] = PYTHON_VERSION
    # Pre-installed distribution: embed it at build time, skip pip install at runtime.
    # PYAPP_DISTRIBUTION_PATH copies the local archive into the binary during cargo build.
    # Do NOT set PYAPP_DISTRIBUTION_SOURCE alongside PATH — that panics.
    env["PYAPP_FULL_ISOLATION"] = "1"
    env["PYAPP_SKIP_INSTALL"] = "1"
    env["PYAPP_DISTRIBUTION_PATH"] = str(PYTHON_PREINSTALLED_ARCHIVE.resolve())
    env["PYAPP_DISTRIBUTION_FORMAT"] = "tar|gzip"
    env["PYAPP_DISTRIBUTION_PYTHON_PATH"] = DIST_PYTHON_PATH
    env["PYAPP_DISTRIBUTION_SITE_PACKAGES_PATH"] = DIST_SITE_PACKAGES
    # Skip UPX compression.
    env["PYAPP_SKIP_COMPRESSION"] = "true"
    # Expose the binary's own path as the PYAPP env var so the installer can
    # write the correct command path into MCP client configs.
    env["PYAPP_PASS_LOCATION"] = "1"

    run(["cargo", "build", "--release"], cwd=PYAPP_DIR, env=env)

    isWindows = platform.system() == "Windows"
    builtBinary = PYAPP_DIR / "target" / "release" / ("pyapp.exe" if isWindows else "pyapp")
    if not builtBinary.exists():
        print(f"ERROR: expected compiled binary at {builtBinary}", file=sys.stderr)
        sys.exit(1)
    return builtBinary


def copyOutput(builtBinary: Path) -> Path:
    print("\n[5/5] Copying output binary...")
    DIST_DIR.mkdir(exist_ok=True)
    isWindows = platform.system() == "Windows"
    outputName = "ffl-mcp.exe" if isWindows else "ffl-mcp"
    outputPath = DIST_DIR / outputName
    shutil.copy2(builtBinary, outputPath)
    outputPath.chmod(outputPath.stat().st_mode | 0o111)
    print(f"\nDone! Binary: {outputPath.resolve()}")
    print(f"Size: {outputPath.stat().st_size / 1_048_576:.1f} MB")
    return outputPath


def clean():
    print("Cleaning build artifacts...")
    for target in [PYAPP_DIR, DIST_DIR, BUILD_CACHE_DIR, Path("pyapp-master.zip")]:
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            print(f"  Removed {target}")


def main():
    parser = argparse.ArgumentParser(description="Build ffl-mcp PyApp executable")
    parser.add_argument("--clean", action="store_true", help="Remove build artifacts first")
    parser.add_argument("--skip-wheel", action="store_true", help="Skip wheel build, reuse existing dist/*.whl")
    parser.add_argument("--skip-download", action="store_true", help="Skip PyApp source download, require pyapp-src/ to exist")
    parser.add_argument("--rebuild-dist", action="store_true", help="Force re-install packages into distribution even if cached")
    args = parser.parse_args()

    if args.clean:
        clean()
        return

    if args.skip_download and not PYAPP_DIR.exists():
        print(f"ERROR: --skip-download requires {PYAPP_DIR}/ to exist", file=sys.stderr)
        sys.exit(1)

    if not args.skip_wheel:
        buildWheel()

    wheelPath = findWheel()
    print(f"  Using wheel: {wheelPath}")

    prepareDistribution(wheelPath, args.rebuild_dist)
    builtBinary = buildPyapp()
    copyOutput(builtBinary)


if __name__ == "__main__":
    main()
