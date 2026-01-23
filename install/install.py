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
import datetime
import importlib.metadata
import json
import os
import pathlib
import shutil
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple


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


def getDefaultClaudeDesktopConfigPath() -> pathlib.Path:
    homePath = pathlib.Path.home()

    if sys.platform == "darwin":
        return homePath / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"

    if os.name == "nt":
        appData = os.environ.get("APPDATA")
        if appData:
            return pathlib.Path(appData) / "Claude" / "claude_desktop_config.json"
        return homePath / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"

    xdgConfigHome = os.environ.get("XDG_CONFIG_HOME")
    if xdgConfigHome:
        return pathlib.Path(xdgConfigHome) / "Claude" / "claude_desktop_config.json"
        
    return homePath / ".config" / "Claude" / "claude_desktop_config.json"


def readJsonFile(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    rawText = path.read_text(encoding="utf-8").strip()
    if not rawText:
        return {}
        
    try:
        data = json.loads(rawText)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")
    return data


def writeJsonAtomic(path: pathlib.Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tempPath = path.with_suffix(path.suffix + ".tmp")
    tempPath.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tempPath.replace(path)


def backupFile(path: pathlib.Path) -> Optional[pathlib.Path]:
    if not path.exists():
        return None
        
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backupPath = path.with_suffix(path.suffix + f".bak_{timestamp}")
    backupPath.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backupPath


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
    if url.startswith("file://"):
        return url

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


def getCodexCliPath() -> Optional[str]:
    envPath = os.environ.get("CODEX_CLI_PATH") or os.environ.get("CODEX_BIN")
    if envPath and pathlib.Path(envPath).exists():
        return envPath

    whichPath = shutil.which("codex")
    if whichPath:
        return whichPath

    homePath = pathlib.Path.home()
    candidatePaths = [
        homePath / ".local" / "bin" / "codex",
        homePath / ".volta" / "bin" / "codex",
        homePath / ".asdf" / "shims" / "codex",
        pathlib.Path("/usr/local/bin/codex"),
        pathlib.Path("/opt/homebrew/bin/codex"),
        pathlib.Path("/usr/bin/codex"),
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
        for candidate in nvmPath.glob("versions/node/*/bin/codex"):
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
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode == 0:
        return
    if allowFailure:
        return
    stderrText = result.stderr.strip()
    stdoutText = result.stdout.strip()
    detailParts = [part for part in [stderrText, stdoutText] if part]
    detail = detailParts[0] if detailParts else "Unknown error"
    raise RuntimeError(f"Command failed: {' '.join(command)}: {detail}")


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


def installCodexCliServer(
    serverName: str,
    uvxFrom: Optional[str],
    entrypoint: str,
    env: Dict[str, str],
    overwrite: bool,
    cliPath: str,
) -> None:
    envArgs = []
    for key in sorted(env.keys()):
        envArgs += ["--env", f"{key}={env[key]}"]

    uvxArgs = buildUvxArgs(uvxFrom, entrypoint)
    command = [cliPath, "mcp", "add"] + envArgs + [serverName, "--", uvxArgs["command"]] + uvxArgs["args"]
    if overwrite:
        runCommand([cliPath, "mcp", "remove", serverName], allowFailure=True)
    runCommand(command)


class DesktopConfigInstaller:
    def __init__(self, configPath: pathlib.Path):
        self.configPath = configPath

    def readConfig(self) -> Dict[str, Any]:
        return readJsonFile(self.configPath)

    def backupConfig(self) -> Optional[pathlib.Path]:
        return backupFile(self.configPath)

    def writeConfig(self, data: Dict[str, Any]) -> None:
        writeJsonAtomic(self.configPath, data)

    def addServer(
        self,
        config: Dict[str, Any],
        serverName: str,
        entry: Dict[str, Any],
        overwrite: bool,
    ) -> Dict[str, Any]:
        
        mcpServers = config.get("mcpServers")
        if mcpServers is None:
            config["mcpServers"] = {}
            mcpServers = config["mcpServers"]
            
        if not isinstance(mcpServers, dict):
            raise ValueError(f"mcpServers in {self.configPath} must be a JSON object")
            
        if serverName in mcpServers and not overwrite:
            raise RuntimeError(
                f"mcpServers['{serverName}'] already exists in {self.configPath}. "
                "Re-run with --overwrite to replace it."
            )

        mcpServers[serverName] = entry
        return config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install ffl-mcp into Claude Desktop config (no manual JSON)."
    )
    parser.add_argument("--config", dest="configPath", help="Path to claude_desktop_config.json (optional).")
    parser.add_argument("--server-name", default="ffl", dest="serverName")
    parser.add_argument("--entrypoint", default="ffl-mcp", dest="entrypoint")
    parser.add_argument("--from", dest="uvxFrom", help="Force uvx --from spec (e.g. git+https://...).")
    parser.add_argument("--overwrite", action="store_true", default=False)
    parser.add_argument("--print", action="store_true", dest="printOnly")
    parser.add_argument("--ffl-bin", dest="fflBin")
    parser.add_argument("--allowed-base-dir", dest="allowedBaseDir")
    parser.add_argument("--use-stdin", choices=["0", "1"], dest="useStdin")
    parser.add_argument("--cli-scope", dest="cliScope", default="user")
    parser.add_argument(
        "--target",
        dest="installTargets",
        default="all",
        help="Comma-separated: all, claude-desktop, claude-cli, codex-cli",
    )
    parser.add_argument("-y", "--yes", action="store_true", dest="assumeYes")
    args = parser.parse_args()

    if args.configPath:
        configPath = pathlib.Path(args.configPath).expanduser().resolve(strict=False)
    else:
        configPath = getDefaultClaudeDesktopConfigPath()

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

    name, entry = buildMcpServerEntry(args.serverName, uvxFrom, args.entrypoint, env)

    if args.printOnly:
        print(json.dumps({name: entry}, ensure_ascii=True, indent=2))
        return

    installTargetsRaw = [part.strip() for part in args.installTargets.split(",")]
    installTargets = [part for part in installTargetsRaw if part]
    if "all" in installTargets:
        installTargets = ["claude-desktop", "claude-cli", "codex-cli"]

    allowedTargets = {"claude-desktop", "claude-cli", "codex-cli"}
    invalidTargets = [part for part in installTargets if part not in allowedTargets]
    if invalidTargets:
        raise ValueError(f"Invalid --install-targets: {', '.join(invalidTargets)}")

    backupPath = None
    if "claude-cli" in installTargets:
        claudeCliPath = getClaudeCliPath()
        if claudeCliPath:
            installClaudeCliServer(
                serverName=args.serverName,
                entry=entry,
                overwrite=args.overwrite,
                scope=args.cliScope,
                cliPath=claudeCliPath,
            )

    if "codex-cli" in installTargets:
        codexCliPath = getCodexCliPath()
        if codexCliPath:
            installCodexCliServer(
                serverName=args.serverName,
                uvxFrom=uvxFrom,
                entrypoint=args.entrypoint,
                env=env,
                overwrite=args.overwrite,
                cliPath=codexCliPath,
            )

    if "claude-desktop" in installTargets:
        installer = DesktopConfigInstaller(configPath)
        config = installer.readConfig()
        updatedConfig = installer.addServer(config, args.serverName, entry, args.overwrite)
        backupPath = installer.backupConfig()
        installer.writeConfig(updatedConfig)

    if "claude-cli" in installTargets and getClaudeCliPath():
        print(f"Installed ffl-mcp into Claude Code CLI (scope: {args.cliScope}).")
    if "codex-cli" in installTargets and getCodexCliPath():
        print("Installed ffl-mcp into Codex CLI.")
    if "claude-desktop" in installTargets:
        print("Installed ffl-mcp into Claude Desktop config.")
        print(f"Config: {configPath}")
        if backupPath:
            print(f"Backup: {backupPath}")
        
    print("Next: restart Claude Desktop (or reload MCP servers if your client supports it).")
    print(f"Server name: {args.serverName}")
    
    if uvxFrom:
        print(f"uvx source: {uvxFrom}")
    else:
        print("uvx source: PyPI (uvx ffl-mcp)")


if __name__ == "__main__":
    main()
