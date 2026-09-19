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

"""Dispatcher entry point for the ffl-mcp standalone binary.

  ffl-mcp.exe            → runs the MCP server (stdio transport)
  ffl-mcp.exe install    → runs the installer, configured to register this
                           binary as the MCP server command (no uvx needed)

PyApp sets the PYAPP env var to the binary path when PYAPP_PASS_LOCATION=1 is
set at build time (see build_pyapp.py). The installer reads FFL_MCP_BINARY to
decide whether to write a direct binary command or a uvx command.
"""

import os
import pathlib
import sys

from importlib.metadata import version

# Must be set before fastmcp is imported (Pydantic settings reads env vars at import time).
os.environ.setdefault("FASTMCP_SHOW_CLI_BANNER", "false")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(version("ffl-mcp"))
        return

    if len(sys.argv) > 1 and sys.argv[1] in {"install", "uninstall"}:
        command = sys.argv.pop(1)

        # PYAPP is set by PyApp to the path of the running binary (ffl-mcp.exe)
        # when PYAPP_PASS_LOCATION=1 is enabled at build time.
        binaryPath = os.environ.get("PYAPP")
        if binaryPath and binaryPath != "1" and os.path.isfile(binaryPath):
            os.environ["FFL_MCP_BINARY"] = binaryPath

        # mcp_install.Install (from the separate `mcp-install` package — see
        # pyproject.toml's [tool.uv.sources]) is generic and reads its app-specific
        # defaults (server name, entrypoint, forwarded env vars, ...) from this
        # manifest rather than hardcoding them — see install.config.json and
        # mcp_install.Install's module docstring. Point it there explicitly since
        # the installed binary's cwd won't generally be the repo root where a bare
        # `install.config.json` would otherwise be auto-discovered.
        appConfigPath = pathlib.Path(__file__).resolve().parent.parent / "install.config.json"
        if appConfigPath.is_file() and "--app-config" not in sys.argv:
            sys.argv.extend(["--app-config", str(appConfigPath)])

        from mcp_install.Install import main as installMain
        if command == "uninstall":
            sys.argv.append("--uninstall")
        installMain()
    else:
        from src.MCP import main as mcpMain
        mcpMain()
