#!/usr/bin/env python3
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
"""Dispatcher entry point for the ffl-mcp standalone binary.

  ffl-mcp.exe            → runs the MCP server (stdio transport)
  ffl-mcp.exe install    → runs the installer, configured to register this
                           binary as the MCP server command (no uvx needed)

PyApp sets the PYAPP env var to the binary path when PYAPP_PASS_LOCATION=1 is
set at build time (see build_pyapp.py). The installer reads FFL_MCP_BINARY to
decide whether to write a direct binary command or a uvx command.
"""

import os
import sys

# Must be set before fastmcp is imported (Pydantic settings reads env vars at import time).
os.environ.setdefault("FASTMCP_SHOW_CLI_BANNER", "false")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        sys.argv.pop(1)

        # PYAPP is set by PyApp to the path of the running binary (ffl-mcp.exe)
        # when PYAPP_PASS_LOCATION=1 is enabled at build time.
        binaryPath = os.environ.get("PYAPP")
        if binaryPath and binaryPath != "1" and os.path.isfile(binaryPath):
            os.environ["FFL_MCP_BINARY"] = binaryPath

        from install.install import main as installMain
        installMain()
    else:
        from src.MCP import main as mcpMain
        mcpMain()
