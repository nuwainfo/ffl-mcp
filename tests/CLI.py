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

r"""Tiny MCP stdio CLI for manually testing ffl-mcp file sharing.

Usage:
    python tests/CLI.py C:\path\to\file.mp4

The CLI starts this repo's MCP server, calls fflShareFile, prints the link,
then waits until Enter/Ctrl+C. Folder shares keep the MCP preview sidecar alive
for endpoints such as /manifest, /file, and /thumb; single-file shares do not
create the preview sidecar.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict, List

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def parseArgs() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Share a file through ffl-mcp over MCP stdio.")
    parser.add_argument("path", help="File or folder path to share.")
    parser.add_argument("--name", help="Optional download name.")
    parser.add_argument("--no-preview", action="store_true", help="Disable folder/multi-file preview mode.")
    parser.add_argument("--max-downloads", type=int, default=0, help="Max downloads for P2P mode. Default: 0.")
    parser.add_argument("--timeout-seconds", type=int, default=1800, help="Inactivity timeout. Default: 1800.")
    parser.add_argument("--wait-link-seconds", type=int, default=30, help="Wait for link generation. Default: 30.")
    parser.add_argument(
        "--hold-seconds",
        type=int,
        help="Keep the share alive for this many seconds, then stop. Default: wait for Enter.",
    )
    parser.add_argument("--e2ee", action="store_true", help="Enable end-to-end encryption.")
    parser.add_argument("--force-relay", action="store_true", help="Disable direct WebRTC and route through relay.")
    parser.add_argument(
        "--server-command",
        nargs=argparse.REMAINDER,
        help="Custom MCP server command. Default: current Python runs src.entrypoint.",
    )
    return parser.parse_args()


def normalizeCommand(command: List[str], repoRoot: pathlib.Path) -> List[str]:
    if not command:
        return command
    executable = pathlib.Path(command[0])
    if not executable.is_absolute():
        candidate = (repoRoot / executable).resolve(strict=False)
        if candidate.exists():
            command = [str(candidate), *command[1:]]
    return command


def extractPayload(result: Any) -> Dict[str, Any]:
    content = getattr(result, "content", None) or []
    if content:
        first = content[0]
        text = getattr(first, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"message": text}

    structured = getattr(result, "structuredContent", None) or getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    return {}


async def run(args: argparse.Namespace) -> int:
    repoRoot = pathlib.Path(__file__).resolve().parents[1]
    sharePath = pathlib.Path(args.path).expanduser().resolve(strict=False)
    if not sharePath.exists():
        print(f"Path does not exist: {sharePath}", file=sys.stderr)
        return 2

    command = args.server_command
    if not command:
        command = [sys.executable, "-c", "import src.entrypoint; src.entrypoint.main()"]
    command = normalizeCommand(command, repoRoot)

    sessionId = None
    print(f"Starting MCP server: {' '.join(command)}", flush=True)
    params = StdioServerParameters(command=command[0], args=command[1:], cwd=str(repoRoot))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            initResult = await session.initialize()
            serverInfo = getattr(initResult, "serverInfo", None) or getattr(initResult, "server_info", None)
            serverName = getattr(serverInfo, "name", "unknown")
            print(f"MCP server: {serverName}", flush=True)

            toolArgs: Dict[str, Any] = {
                "path": str(sharePath),
                "preview": not args.no_preview,
                "maxDownloads": args.max_downloads,
                "timeoutSeconds": args.timeout_seconds,
                "waitLinkSeconds": args.wait_link_seconds,
                "e2ee": args.e2ee,
                "forceRelay": args.force_relay,
            }
            if args.name:
                toolArgs["name"] = args.name

            try:
                result = await session.call_tool("fflShareFile", toolArgs)
                payload = extractPayload(result)

                sessionId = payload.get("sessionId")
                link = payload.get("link")
                print("", flush=True)
                print(f"Link: {link}", flush=True)
                print(f"Session: {sessionId}", flush=True)
                print("", flush=True)
                print("Keep this process running while you test the link/preview.", flush=True)
                if args.hold_seconds is not None:
                    print(f"Stopping automatically in {args.hold_seconds} seconds...", flush=True)
                    await anyio.sleep(max(0, args.hold_seconds))
                else:
                    await anyio.to_thread.run_sync(input, "Press Enter to stop the share session...")
                return 0
            finally:
                if sessionId:
                    try:
                        await session.call_tool("fflStopSession", {"sessionId": sessionId})
                    except Exception as exc:
                        print(f"Failed to stop session cleanly: {exc}", file=sys.stderr)


def main() -> int:
    return anyio.run(run, parseArgs())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
