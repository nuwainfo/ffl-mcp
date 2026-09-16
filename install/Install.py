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

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple

from install.Backends import (
    JsonMcpBackend,
    TomlMcpBackend,
    getDefaultClaudeDesktopConfigPath,
    getDefaultCodexConfigPath,
    getDefaultGrokConfigPath,
)


envKeys = [
    "FFL_BIN",
    "FFL_RUN_MODE",
    "FFL_PYTHON",
    "FFL_CORE_PATH",
    "FFL_COMMAND",
    "FFL_USE_STDIN",
    "FFL_WAIT_LINK_SECONDS",
    "ALLOWED_BASE_DIR",
]


def inferUvxFromSpec() -> Optional[str]:
    try:
        distInfo = importlib.metadata.distribution("ffl-mcp")
    except importlib.metadata.PackageNotFoundError:
        return None

    directUrlText = distInfo.read_text("direct_url.json")
    if not directUrlText:
        return None

    try:
        info = json.loads(directUrlText)
    except json.JSONDecodeError:
        return None

    url = info.get("url")
    vcsInfo = info.get("vcs_info") or {}

    if not isinstance(url, str) or not url:
        return None
    # file:// URLs are local paths (e.g. bundled wheels) — useless as a uvx source
    if url.startswith("file://"):
        return None

    if url.startswith("git+"):
        return url

    if isinstance(vcsInfo, dict) and vcsInfo:
        return "git+" + url

    if url.startswith(("https://", "ssh://", "git://")):
        if url.endswith(".git") or "github.com" in url or "gitlab.com" in url or "bitbucket.org" in url:
            return "git+" + url

    return None


def collectEnv(overrides: Dict[str, str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for key in envKeys:
        value = overrides.get(key)
        if value is None:
            value = os.environ.get(key)

        if value is None or value == "":
            continue

        env[key] = value

    return env


def buildMcpServerEntry(
    serverName: str,
    uvxFrom: Optional[str],
    entrypoint: str,
    env: Dict[str, str],
) -> Tuple[str, Dict[str, Any]]:
    if uvxFrom:
        args = ["--from", uvxFrom, entrypoint]
    else:
        args = [entrypoint]

    entry: Dict[str, Any] = {"command": "uvx", "args": args}
    if env:
        entry["env"] = env
    return serverName, entry


def getClaudeCliPath() -> Optional[str]:
    envPath = os.environ.get("CLAUDE_CLI_PATH") or os.environ.get("CLAUDE_BIN")
    if envPath and pathlib.Path(envPath).exists():
        return envPath

    whichPath = shutil.which("claude")
    if whichPath:
        return whichPath

    homePath = pathlib.Path.home()
    candidatePaths = [
        homePath / ".local" / "bin" / "claude",
        homePath / ".volta" / "bin" / "claude",
        homePath / ".asdf" / "shims" / "claude",
        pathlib.Path("/usr/local/bin/claude"),
        pathlib.Path("/opt/homebrew/bin/claude"),
        pathlib.Path("/usr/bin/claude"),
    ]
    for candidate in candidatePaths:
        if candidate.exists():
            return str(candidate)

    nvmRoots = [os.environ.get("NVM_DIR"), str(homePath / ".nvm")]
    for nvmRoot in nvmRoots:
        if not nvmRoot:
            continue
        nvmPath = pathlib.Path(nvmRoot)
        if not nvmPath.exists():
            continue
        for candidate in nvmPath.glob("versions/node/*/bin/claude"):
            if candidate.exists():
                return str(candidate)
    return None


def buildUvxArgs(uvxFrom: Optional[str], entrypoint: str) -> Dict[str, Any]:
    args = ["uvx"]
    if uvxFrom:
        args += ["--from", uvxFrom]
    args.append(entrypoint)
    return {"command": args[0], "args": args[1:]}


def runCommand(command: list[str], allowFailure: bool = False) -> None:
    result = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode == 0:
        return
    if allowFailure:
        return
    stderrText = result.stderr.strip()
    stdoutText = result.stdout.strip()
    detailParts = [part for part in [stderrText, stdoutText] if part]
    detail = detailParts[0] if detailParts else "Unknown error"
    raise RuntimeError(f"Command failed: {' '.join(command)}: {detail}")


def warmPyappBinary(binaryPath: Optional[str]) -> None:
    if not binaryPath:
        return
    try:
        subprocess.run(
            [binaryPath, "--help"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except Exception:
        # Best effort only. Registration should still succeed even if warming fails.
        return


def installClaudeCliServer(
    serverName: str,
    entry: Dict[str, Any],
    overwrite: bool,
    scope: str,
    cliPath: str,
) -> None:
    command = [
        cliPath,
        "mcp",
        "add-json",
        "-s",
        scope,
        serverName,
        json.dumps(entry, ensure_ascii=True),
    ]
    if overwrite:
        runCommand([cliPath, "mcp", "remove", "-s", scope, serverName], allowFailure=True)
    runCommand(command)


def uninstallClaudeCliServer(serverName: str, scope: str, cliPath: str) -> None:
    runCommand([cliPath, "mcp", "remove", "-s", scope, serverName], allowFailure=True)


targetAliases = {
    "claude-cli": "claude-code",
    "codex-cli": "codex",
    "codex-desktop": "codex",
    "grok": "grok-build",
}


def normalizeInstallTargets(rawTargets: list[str]) -> list[str]:
    if "all" in rawTargets:
        rawTargets = ["claude-desktop", "claude-code", "codex", "grok-build"]

    targets = []
    for target in rawTargets:
        normalizedTarget = targetAliases.get(target, target)
        if normalizedTarget not in targets:
            targets.append(normalizedTarget)

    allowedTargets = {"claude-desktop", "claude-code", "codex", "grok-build"}
    invalidTargets = [target for target in targets if target not in allowedTargets]
    if invalidTargets:
        raise ValueError(f"Invalid --target: {', '.join(invalidTargets)}")
    return targets


def buildConfigBackends(
    claudeConfigPath: pathlib.Path,
    codexConfigPath: pathlib.Path,
    grokConfigPath: pathlib.Path,
) -> Dict[str, Any]:
    return {
        "claude-desktop": JsonMcpBackend("claude-desktop", "Claude Desktop", claudeConfigPath),
        "codex": TomlMcpBackend("codex", "Codex", codexConfigPath),
        "grok-build": TomlMcpBackend("grok-build", "Grok Build", grokConfigPath),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install ffl-mcp into supported MCP clients."
    )
    parser.add_argument("--config", dest="configPath", help="Path to claude_desktop_config.json (optional).")
    parser.add_argument("--codex-config", dest="codexConfigPath", help="Path to Codex config.toml (optional).")
    parser.add_argument("--grok-config", dest="grokConfigPath", help="Path to Grok config.toml (optional).")
    parser.add_argument("--server-name", default="ffl", dest="serverName")
    parser.add_argument("--entrypoint", default="ffl-mcp", dest="entrypoint")
    parser.add_argument("--from", dest="uvxFrom", help="Force uvx --from spec (e.g. git+https://...).")
    parser.add_argument("--overwrite", action="store_true", default=False)
    parser.add_argument("--uninstall", action="store_true", default=False)
    parser.add_argument("--print", action="store_true", dest="printOnly")
    parser.add_argument("--ffl-bin", dest="fflBin")
    parser.add_argument("--allowed-base-dir", dest="allowedBaseDir")
    parser.add_argument("--use-stdin", choices=["0", "1"], dest="useStdin")
    parser.add_argument("--cli-scope", dest="cliScope", default="user")
    parser.add_argument(
        "--target",
        dest="installTargets",
        default="all",
        help=(
            "Comma-separated: all, claude-desktop, claude-code, codex, grok-build. "
            "Legacy aliases: claude-cli, codex-cli, codex-desktop, grok."
        ),
    )
    parser.add_argument("-y", "--yes", action="store_true", dest="assumeYes")
    args = parser.parse_args()

    if args.configPath:
        configPath = pathlib.Path(args.configPath).expanduser().resolve(strict=False)
    else:
        configPath = getDefaultClaudeDesktopConfigPath()

    if args.codexConfigPath:
        codexConfigPath = pathlib.Path(args.codexConfigPath).expanduser().resolve(strict=False)
    else:
        codexConfigPath = getDefaultCodexConfigPath()

    if args.grokConfigPath:
        grokConfigPath = pathlib.Path(args.grokConfigPath).expanduser().resolve(strict=False)
    else:
        grokConfigPath = getDefaultGrokConfigPath()

    uvxFrom = args.uvxFrom or inferUvxFromSpec()

    envOverrides: Dict[str, str] = {}
    if args.fflBin:
        envOverrides["FFL_BIN"] = args.fflBin
    if args.allowedBaseDir:
        envOverrides["ALLOWED_BASE_DIR"] = args.allowedBaseDir
    if args.useStdin:
        envOverrides["FFL_USE_STDIN"] = args.useStdin

    env = collectEnv(envOverrides)
    if "FFL_USE_STDIN" not in env:
        env["FFL_USE_STDIN"] = "1"

    if "ALLOWED_BASE_DIR" not in env:
        print("Warning: ALLOWED_BASE_DIR is not set. This allows sharing any path.")
        print("Recommended: set --allowed-base-dir to restrict file sharing.")

    # When running as a standalone PyApp binary, register the binary itself as
    # the MCP server command so end-users don't need uvx or Python installed.
    binaryPath = os.environ.get("FFL_MCP_BINARY")
    if binaryPath:
        entry: Dict[str, Any] = {"command": binaryPath, "args": []}
        if env:
            entry["env"] = env
        name = args.serverName
    else:
        name, entry = buildMcpServerEntry(args.serverName, uvxFrom, args.entrypoint, env)

    if args.printOnly and args.uninstall:
        raise ValueError("--print cannot be combined with --uninstall")
    if args.printOnly:
        print(json.dumps({name: entry}, ensure_ascii=True, indent=2))
        return

    installTargetsRaw = [part.strip() for part in args.installTargets.split(",") if part.strip()]
    installTargets = normalizeInstallTargets(installTargetsRaw)
    configBackends = buildConfigBackends(configPath, codexConfigPath, grokConfigPath)
    completedTargets = []

    if "claude-code" in installTargets:
        claudeCliPath = getClaudeCliPath()
        if claudeCliPath is None:
            print("Warning: Claude Code CLI was not found; skipped claude-code.")
        elif args.uninstall:
            uninstallClaudeCliServer(args.serverName, args.cliScope, claudeCliPath)
            print(f"Removed ffl-mcp from Claude Code CLI (scope: {args.cliScope}).")
            completedTargets.append("claude-code")
        else:
            installClaudeCliServer(
                serverName=args.serverName,
                entry=entry,
                overwrite=args.overwrite,
                scope=args.cliScope,
                cliPath=claudeCliPath,
            )
            print(f"Installed ffl-mcp into Claude Code CLI (scope: {args.cliScope}).")
            completedTargets.append("claude-code")

    for target in installTargets:
        backend = configBackends.get(target)
        if backend is None:
            continue
        result = backend.uninstall(args.serverName) if args.uninstall else backend.install(
            args.serverName,
            entry,
            args.overwrite,
        )
        action = "Removed" if args.uninstall else "Installed"
        print(f"{action} ffl-mcp {'from' if args.uninstall else 'into'} {result.label} config.")
        print(f"Config: {result.configPath}")
        if result.backupPath:
            print(f"Backup: {result.backupPath}")
        if not result.changed:
            print("No existing ffl-mcp entry was found.")
        completedTargets.append(target)

    if not args.uninstall:
        warmPyappBinary(binaryPath)

    if any(target in completedTargets for target in {"claude-desktop", "codex", "grok-build"}):
        print("\nNext: restart your MCP client or reload its MCP servers.")
    elif "claude-code" in completedTargets:
        print("\nNext: restart Claude Code or reload MCP servers.")

    print(f"Server name: {args.serverName}")

    if binaryPath:
        print(f"Binary: {binaryPath}")
    elif uvxFrom:
        print(f"uvx source: {uvxFrom}")
    else:
        print("uvx source: PyPI (uvx ffl-mcp)")


if __name__ == "__main__":
    main()
