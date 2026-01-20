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
        
    if not isinstance(vcsInfo, dict) or not vcsInfo:
        return None

    if url.startswith("git+"):
        return url
        
    return "git+" + url


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
    if "ALLOWED_BASE_DIR" not in env:
        env["ALLOWED_BASE_DIR"] = str(pathlib.Path.home() / "Downloads")
    if "FFL_USE_STDIN" not in env:
        env["FFL_USE_STDIN"] = "1"

    name, entry = buildMcpServerEntry(args.serverName, uvxFrom, args.entrypoint, env)

    if args.printOnly:
        print(json.dumps({name: entry}, ensure_ascii=True, indent=2))
        return

    installer = DesktopConfigInstaller(configPath)
    config = installer.readConfig()
    updatedConfig = installer.addServer(config, args.serverName, entry, args.overwrite)
    backupPath = installer.backupConfig()
    installer.writeConfig(updatedConfig)

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
