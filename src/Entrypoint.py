#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
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

"""Dispatcher entry point for ffl-mcp and its installer."""

import os
import pathlib
import sys

from importlib.metadata import version

from .NetworkProfile import prepareInstallerArguments

# Must be set before fastmcp is imported (Pydantic settings reads env vars at import time).
os.environ.setdefault("FASTMCP_SHOW_CLI_BANNER", "false")


def hasOption(arguments: list[str], option: str) -> bool:
    return option in arguments or any(argument.startswith(f"{option}=") for argument in arguments)


def runInstaller(arguments: list[str]) -> None:
    """Register ffl-mcp after adding this install host's network profile."""
    binaryPath = os.environ.get("PYAPP")
    if binaryPath and binaryPath != "1" and os.path.isfile(binaryPath):
        os.environ["FFL_MCP_BINARY"] = binaryPath

    appConfigPath = pathlib.Path(__file__).resolve().parent.parent / "install.config.json"
    if appConfigPath.is_file() and not hasOption(arguments, "--app-config"):
        arguments.extend(["--app-config", str(appConfigPath)])

    sys.argv = [sys.argv[0], *prepareInstallerArguments(arguments)]
    from mcp_install.Install import main as installMain
    installMain()


def install() -> None:
    """Console-script entry point for the install command."""
    runInstaller(sys.argv[1:])


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(version("ffl-mcp"))
        return

    if len(sys.argv) > 1 and sys.argv[1] in {"install", "uninstall"}:
        command = sys.argv.pop(1)
        arguments = sys.argv[1:]
        if command == "uninstall":
            arguments.append("--uninstall")

        runInstaller(arguments)
        return

    from .MCP import main as mcpMain
    mcpMain()
