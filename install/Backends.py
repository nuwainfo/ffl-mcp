#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0

"""Native MCP-client configuration backends.

MCP standardizes the protocol between a host and a server, but each host owns
its own registration format and location.  Keep those details here so the
command-line installer only selects and orchestrates backends.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


def getDefaultClaudeDesktopConfigPath() -> pathlib.Path:
    homePath = pathlib.Path.home()

    if os.name == "nt":
        appData = os.environ.get("APPDATA")
        if appData:
            return pathlib.Path(appData) / "Claude" / "claude_desktop_config.json"
        return homePath / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"

    if os.sys.platform == "darwin":
        return homePath / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"

    xdgConfigHome = os.environ.get("XDG_CONFIG_HOME")
    if xdgConfigHome:
        return pathlib.Path(xdgConfigHome) / "Claude" / "claude_desktop_config.json"

    return homePath / ".config" / "Claude" / "claude_desktop_config.json"


def getDefaultCodexConfigPath() -> pathlib.Path:
    return pathlib.Path.home() / ".codex" / "config.toml"


def getDefaultGrokConfigPath() -> pathlib.Path:
    grokHome = os.environ.get("GROK_HOME")
    if grokHome:
        return pathlib.Path(grokHome).expanduser() / "config.toml"

    return pathlib.Path.home() / ".grok" / "config.toml"


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


def writeTextAtomic(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tempPath = path.with_suffix(path.suffix + ".tmp")
    tempPath.write_text(text, encoding="utf-8")
    tempPath.replace(path)


def backupFile(path: pathlib.Path) -> Optional[pathlib.Path]:
    if not path.exists():
        return None

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backupPath = path.with_suffix(path.suffix + f".bak_{timestamp}")
    backupPath.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backupPath


def tomlString(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def tomlArray(values: list[str]) -> str:
    return "[" + ", ".join(tomlString(value) for value in values) + "]"


def tomlKey(key: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]+", key):
        return key
    return tomlString(key)


def buildTomlServerConfig(serverName: str, entry: Dict[str, Any]) -> str:
    key = tomlKey(serverName)
    lines = [
        f"[mcp_servers.{key}]",
        f"command = {tomlString(str(entry['command']))}",
    ]

    args = entry.get("args")
    if args:
        lines.append(f"args = {tomlArray([str(arg) for arg in args])}")

    env = entry.get("env")
    if env:
        lines.append("")
        lines.append(f"[mcp_servers.{key}.env]")
        for envKey in sorted(env.keys()):
            lines.append(f"{tomlKey(envKey)} = {tomlString(str(env[envKey]))}")

    return "\n".join(lines) + "\n"


def removeTomlServerConfig(existingText: str, serverName: str) -> Tuple[str, bool]:
    key = tomlKey(serverName)
    sectionPrefixes = [f"mcp_servers.{key}", f"mcp_servers.{tomlString(serverName)}"]
    lines = existingText.splitlines(keepends=True)
    keptLines = []
    skipping = False
    removed = False

    for line in lines:
        match = re.match(r"\s*\[([^\]]+)\]\s*(?:#.*)?$", line)
        if match:
            sectionName = match.group(1).strip()
            skipping = any(
                sectionName == prefix or sectionName.startswith(prefix + ".")
                for prefix in sectionPrefixes
            )
            if skipping:
                removed = True
                continue
        if skipping:
            continue
        keptLines.append(line)

    return "".join(keptLines).rstrip() + ("\n" if keptLines else ""), removed


@dataclass(frozen=True)
class InstallResult:
    target: str
    label: str
    configPath: pathlib.Path
    backupPath: Optional[pathlib.Path]
    changed: bool


class ConfigBackend:
    """A client-owned config file that can register one stdio MCP server."""

    def __init__(self, target: str, label: str, configPath: pathlib.Path):
        self.target = target
        self.label = label
        self.configPath = configPath

    def install(self, serverName: str, entry: Dict[str, Any], overwrite: bool) -> InstallResult:
        raise NotImplementedError

    def uninstall(self, serverName: str) -> InstallResult:
        raise NotImplementedError


class JsonMcpBackend(ConfigBackend):
    """Claude Desktop's JSON ``mcpServers`` configuration."""

    def install(self, serverName: str, entry: Dict[str, Any], overwrite: bool) -> InstallResult:
        config = readJsonFile(self.configPath)
        mcpServers = config.get("mcpServers")
        if mcpServers is None:
            mcpServers = {}
            config["mcpServers"] = mcpServers
        if not isinstance(mcpServers, dict):
            raise ValueError(f"mcpServers in {self.configPath} must be a JSON object")
        if serverName in mcpServers and not overwrite:
            raise RuntimeError(
                f"mcpServers['{serverName}'] already exists in {self.configPath}. "
                "Re-run with --overwrite to replace it."
            )

        mcpServers[serverName] = entry
        backupPath = backupFile(self.configPath)
        writeJsonAtomic(self.configPath, config)
        return InstallResult(self.target, self.label, self.configPath, backupPath, changed=True)

    def uninstall(self, serverName: str) -> InstallResult:
        config = readJsonFile(self.configPath)
        mcpServers = config.get("mcpServers")
        if not isinstance(mcpServers, dict) or serverName not in mcpServers:
            return InstallResult(self.target, self.label, self.configPath, None, changed=False)

        del mcpServers[serverName]
        backupPath = backupFile(self.configPath)
        writeJsonAtomic(self.configPath, config)
        return InstallResult(self.target, self.label, self.configPath, backupPath, changed=True)


class TomlMcpBackend(ConfigBackend):
    """Codex and Grok Build's ``mcp_servers`` TOML configuration."""

    def install(self, serverName: str, entry: Dict[str, Any], overwrite: bool) -> InstallResult:
        configText = self.configPath.read_text(encoding="utf-8") if self.configPath.exists() else ""
        configWithoutServer, removed = removeTomlServerConfig(configText, serverName)
        if removed and not overwrite:
            raise RuntimeError(
                f"mcp_servers['{serverName}'] already exists in {self.configPath}. "
                "Re-run with --overwrite to replace it."
            )

        serverText = buildTomlServerConfig(serverName, entry)
        updatedText = configWithoutServer.rstrip() + "\n\n" + serverText if configWithoutServer.strip() else serverText
        backupPath = backupFile(self.configPath)
        writeTextAtomic(self.configPath, updatedText)
        return InstallResult(self.target, self.label, self.configPath, backupPath, changed=True)

    def uninstall(self, serverName: str) -> InstallResult:
        configText = self.configPath.read_text(encoding="utf-8") if self.configPath.exists() else ""
        updatedText, removed = removeTomlServerConfig(configText, serverName)
        if not removed:
            return InstallResult(self.target, self.label, self.configPath, None, changed=False)

        backupPath = backupFile(self.configPath)
        writeTextAtomic(self.configPath, updatedText)
        return InstallResult(self.target, self.label, self.configPath, backupPath, changed=True)
