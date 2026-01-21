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

import argparse
import base64
import json
import logging
import os
import pathlib
import shlex
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastmcp import FastMCP


logger = logging.getLogger("fflMcp")
logger.setLevel(logging.DEBUG)

mcp = FastMCP("ffl-mcp")

def resolveDefaultFflBin() -> str:
    localFfl = pathlib.Path(__file__).resolve().parent / "ffl.com"
    if localFfl.exists():
        if not os.access(localFfl, os.X_OK):
            os.chmod(localFfl, 0o755)
        return str(localFfl)
    return "ffl"


defaultWaitLinkSeconds = int(os.environ.get("FFL_WAIT_LINK_SECONDS", "20"))
allowedBaseDir = os.environ.get("ALLOWED_BASE_DIR")
fflRunMode = os.environ.get("FFL_RUN_MODE", "binary").lower()
fflBin = os.environ.get("FFL_BIN", resolveDefaultFflBin())
fflPython = os.environ.get("FFL_PYTHON", "python")
fflCorePath = os.environ.get("FFL_CORE_PATH")
fflCommandOverride = os.environ.get("FFL_COMMAND")
fflUseStdin = os.environ.get("FFL_USE_STDIN", "").lower() in ("1", "true", "yes")
fflShellMode = os.environ.get("FFL_SHELL", "").lower() in ("1", "true", "yes")
fflUseHook = os.environ.get("FFL_USE_HOOK", "1").lower() in ("1", "true", "yes")
fflHookHost = os.environ.get("FFL_HOOK_HOST", "127.0.0.1")
fflHookPath = os.environ.get("FFL_HOOK_PATH", "/events")
fflHookUsername = os.environ.get("FFL_HOOK_USERNAME", "ffl-mcp")
fflHookPassword = os.environ.get("FFL_HOOK_PASSWORD")
fflHookMaxEvents = int(os.environ.get("FFL_HOOK_MAX_EVENTS", "200"))


def parseBasicAuthHeader(headerValue: Optional[str]) -> Optional[Dict[str, str]]:
    if not headerValue:
        return None
    if not headerValue.startswith("Basic "):
        return None
    encoded = headerValue[len("Basic ") :].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    userName, password = decoded.split(":", 1)
    return {"userName": userName, "password": password}


class HookRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.debug("Hook request: %s", format % args)

    def do_POST(self):
        hookServer = self.server
        if not hookServer.isAuthorized(self.headers.get("Authorization")):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="ffl-mcp"')
            self.end_headers()
            return

        if hookServer.path and self.path != hookServer.path:
            self.send_response(404)
            self.end_headers()
            return

        contentLength = int(self.headers.get("Content-Length", "0"))
        if contentLength == 0:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"empty body"}')
            return

        try:
            requestBody = self.rfile.read(contentLength)
            data = json.loads(requestBody.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"invalid json: {exc}"}).encode("utf-8"))
            return

        eventName = data.get("event")
        eventData = data.get("data", {})
        if not eventName:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"missing event"}')
            return

        try:
            hookServer.handleEvent(eventName, eventData)
        except Exception as exc:
            logger.warning("Hook handler error: %s", exc)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"handler error: {exc}"}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')


class HookServer(ThreadingHTTPServer):
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        username: str,
        password: Optional[str],
        maxEvents: int,
    ):
        super().__init__((host, port), HookRequestHandler)
        self.host = host
        self.port = self.server_address[1]
        self.path = path
        self.username = username
        self.password = password if password else uuid.uuid4().hex
        self.maxEvents = maxEvents
        self._eventLock = threading.Lock()
        self._events: List[Dict[str, Any]] = []
        self._linkValue: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def isAuthorized(self, headerValue: Optional[str]) -> bool:
        if not self.username:
            return True
        authData = parseBasicAuthHeader(headerValue)
        if not authData:
            return False
        return authData["userName"] == self.username and authData["password"] == self.password

    def start(self) -> None:
        if self._running:
            raise RuntimeError("Hook server already running")
        self._running = True
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.shutdown()
        self.server_close()

    def getHookUrl(self) -> str:
        authPart = f"{quote(self.username)}:{quote(self.password)}@" if self.username else ""
        return f"http://{authPart}{self.host}:{self.port}{self.path}"

    def handleEvent(self, eventName: str, eventData: Any) -> None:
        entry = {"event": eventName, "data": eventData, "timestamp": time.time()}
        with self._eventLock:
            self._events.append(entry)
            if len(self._events) > self.maxEvents:
                self._events = self._events[-self.maxEvents :]
        if eventName == "/share/link/create" and isinstance(eventData, dict):
            linkValue = eventData.get("link") or eventData.get("shareLink")
            if isinstance(linkValue, str):
                self._linkValue = linkValue

    def getLink(self) -> Optional[str]:
        return self._linkValue

    def getEvents(self, limit: int) -> List[Dict[str, Any]]:
        if limit <= 0:
            return []
        with self._eventLock:
            return list(self._events[-limit:])

    def getEventCount(self) -> int:
        with self._eventLock:
            return len(self._events)


class SessionStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def addSession(self, sessionInfo: Dict[str, Any]) -> None:
        with self.lock:
            self.sessions[sessionInfo["sessionId"]] = sessionInfo

    def listSessions(self) -> List[Dict[str, Any]]:
        self.pruneSessions()
        now = time.time()
        with self.lock:
            return [
                {
                    "sessionId": sessionId,
                    "pid": info["process"].pid,
                    "link": info["link"],
                    "ageSeconds": int(now - info["startedAt"]),
                    "cmd": info["command"],
                    "eventCount": info["hookServer"].getEventCount() if info.get("hookServer") else 0,
                }
                for sessionId, info in self.sessions.items()
            ]

    def getSession(self, sessionId: str) -> Optional[Dict[str, Any]]:
        self.pruneSessions()
        with self.lock:
            return self.sessions.get(sessionId)

    def stopSession(self, sessionId: str) -> Dict[str, Any]:
        sessionInfo = self.getSession(sessionId)
        if not sessionInfo:
            return {"ok": False, "error": "not_found"}

        process = sessionInfo["process"]
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception as exc:
            logger.warning("Failed to terminate session %s: %s", sessionId, exc)
        finally:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception as exc:
                    logger.warning("Failed to kill session %s: %s", sessionId, exc)

        self.cleanupSession(sessionId)
        return {"ok": True, "sessionId": sessionId}

    def cleanupSession(self, sessionId: str) -> None:
        with self.lock:
            sessionInfo = self.sessions.pop(sessionId, None)
        if not sessionInfo:
            return
        hookServer = sessionInfo.get("hookServer")
        if hookServer:
            try:
                hookServer.stop()
            except Exception as exc:
                logger.debug("Failed to stop hook server for %s: %s", sessionId, exc)
        for path in sessionInfo.get("tempPaths", []):
            try:
                os.remove(path)
            except Exception as exc:
                logger.debug("Failed to remove temp file %s: %s", path, exc)

    def pruneSessions(self) -> None:
        with self.lock:
            endedSessionIds = [
                sessionId
                for sessionId, info in self.sessions.items()
                if info["process"].poll() is not None
            ]
        for sessionId in endedSessionIds:
            self.cleanupSession(sessionId)


sessionStore = SessionStore()


def configureLogging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def getAllowedBaseDir() -> Optional[pathlib.Path]:
    if not allowedBaseDir:
        return None
    return pathlib.Path(allowedBaseDir).expanduser().resolve()


def isPathAllowed(path: pathlib.Path) -> bool:
    baseDir = getAllowedBaseDir()
    if not baseDir:
        return True
    resolvedPath = path.expanduser().resolve()
    return resolvedPath == baseDir or baseDir in resolvedPath.parents


def readJsonLink(jsonPath: str) -> Optional[str]:
    try:
        with open(jsonPath, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        logger.debug("JSON not ready yet at %s: %s", jsonPath, exc)
        return None
    link = data.get("link")
    if isinstance(link, str) and link.startswith("http"):
        return link
    return None


def waitForLink(jsonPath: str, waitSeconds: int, hookServer: Optional[HookServer]) -> str:
    deadline = time.time() + max(1, waitSeconds)
    while time.time() < deadline:
        if hookServer:
            linkValue = hookServer.getLink()
            if linkValue:
                return linkValue
        if os.path.exists(jsonPath):
            link = readJsonLink(jsonPath)
            if link:
                return link
        time.sleep(0.15)
    raise RuntimeError(
        f"ffl did not produce a link within {waitSeconds}s. "
        "Check your FFL_BIN/FFL_CORE_PATH configuration."
    )


def createTempFile(fileName: str, data: bytes) -> str:
    suffix = pathlib.Path(fileName).suffix
    tempFile = tempfile.NamedTemporaryFile(prefix="ffl_", suffix=suffix, delete=False)
    tempFile.write(data)
    tempFile.close()
    return tempFile.name


def buildBaseCommand() -> List[str]:
    if fflCommandOverride:
        return shlex.split(fflCommandOverride)
    if fflRunMode == "python":
        if not fflCorePath:
            raise ValueError("FFL_CORE_PATH is required when FFL_RUN_MODE=python")
        return [fflPython, fflCorePath, "--cli"]
    return [fflBin]


def shouldUseShell(command: List[str]) -> bool:
    if fflShellMode:
        return True
    if not command:
        return False
    return command[0].endswith(".com")


def buildShareArgs(
    shareTarget: str,
    name: Optional[str],
    e2ee: bool,
    authUser: Optional[str],
    authPassword: Optional[str],
    maxDownloads: int,
    timeoutSeconds: int,
    hookUrl: Optional[str],
    proxy: Optional[str],
) -> List[str]:
    args = [shareTarget, "--max-downloads", str(maxDownloads), "--timeout", str(timeoutSeconds)]
    if name:
        args += ["--name", name]
    if e2ee:
        args.append("--e2ee")
    if authUser:
        args += ["--auth-user", authUser]
    if authPassword:
        args += ["--auth-password", authPassword]
    if hookUrl:
        args += ["--hook", hookUrl]
    if proxy:
        args += ["--proxy", proxy]
    return args


def startHookServerIfNeeded(hookUrl: Optional[str]) -> Dict[str, Any]:
    if hookUrl or not fflUseHook:
        return {"hookServer": None, "hookUrl": hookUrl}

    hookServer = HookServer(
        host=fflHookHost,
        port=0,
        path=fflHookPath,
        username=fflHookUsername,
        password=fflHookPassword,
        maxEvents=fflHookMaxEvents,
    )
    hookServer.start()
    return {"hookServer": hookServer, "hookUrl": hookServer.getHookUrl()}


def spawnFflAndWaitLink(
    fflArgs: List[str],
    stdinBytes: Optional[bytes],
    waitSeconds: int,
    tempPaths: Optional[List[str]] = None,
    hookServer: Optional[HookServer] = None,
) -> Dict[str, Any]:
    tempPaths = tempPaths or []
    jsonTemp = tempfile.NamedTemporaryFile(prefix="ffl_", suffix=".json", delete=False)
    jsonPath = jsonTemp.name
    jsonTemp.close()
    tempPaths.append(jsonPath)

    command = buildBaseCommand() + fflArgs + ["--json", jsonPath]
    useShell = shouldUseShell(command)

    logger.info("Starting ffl: %s", shlex.join(command))

    if useShell:
        commandText = shlex.join(command)
        process = subprocess.Popen(
            commandText,
            shell=True,
            stdin=subprocess.PIPE if stdinBytes is not None else None,
            #stdout=subprocess.DEVNULL,
            #stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__),
        )
    else:
        process = subprocess.Popen(
            command,
            shell=False,
            stdin=subprocess.PIPE if stdinBytes is not None else None,
            #stdout=subprocess.DEVNULL,
            #stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__),
        )

    if stdinBytes is not None and process.stdin is not None:
        process.stdin.write(stdinBytes)
        process.stdin.close()

    try:
        link = waitForLink(jsonPath, waitSeconds, hookServer)
    except Exception:
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception as exc:
            logger.debug("Failed to terminate ffl process: %s", exc)
        finally:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception as exc:
                    logger.debug("Failed to kill ffl process: %s", exc)
        if hookServer:
            try:
                hookServer.stop()
            except Exception as exc:
                logger.debug("Failed to stop hook server: %s", exc)
        for path in tempPaths:
            try:
                os.remove(path)
            except Exception as exc:
                logger.debug("Failed to remove temp file %s: %s", path, exc)
        raise

    sessionId = str(uuid.uuid4())
    sessionStore.addSession(
        {
            "sessionId": sessionId,
            "process": process,
            "link": link,
            "startedAt": time.time(),
            "jsonPath": jsonPath,
            "command": command,
            "tempPaths": tempPaths,
            "hookServer": hookServer,
        }
    )

    return {"sessionId": sessionId, "link": link, "pid": process.pid, "jsonPath": jsonPath, "cmd": command}


@mcp.tool
def fflShareText(
    text: str,
    name: str = "shared.txt",
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    waitLinkSeconds: int = defaultWaitLinkSeconds,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Share a short text using ffl. Returns a sessionId and link.
    """
    tempPaths: List[str] = []
    hookInfo = startHookServerIfNeeded(hookUrl)
    hookServer = hookInfo["hookServer"]
    effectiveHookUrl = hookInfo["hookUrl"]
    if fflUseStdin:
        args = buildShareArgs(
            "-",
            name,
            e2ee,
            authUser,
            authPassword,
            maxDownloads,
            timeoutSeconds,
            effectiveHookUrl,
            proxy,
        )
        return spawnFflAndWaitLink(args, text.encode("utf-8"), waitLinkSeconds, tempPaths, hookServer)

    tempPath = createTempFile(name, text.encode("utf-8"))
    tempPaths.append(tempPath)
    args = buildShareArgs(
        tempPath,
        name,
        e2ee,
        authUser,
        authPassword,
        maxDownloads,
        timeoutSeconds,
        effectiveHookUrl,
        proxy,
    )
    return spawnFflAndWaitLink(args, None, waitLinkSeconds, tempPaths, hookServer)


@mcp.tool
def fflShareBase64(
    dataB64: str,
    name: str = "data.bin",
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    waitLinkSeconds: int = defaultWaitLinkSeconds,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Share arbitrary base64 bytes using ffl. Returns a sessionId and link.
    """
    rawBytes = base64.b64decode(dataB64, validate=True)
    tempPaths: List[str] = []
    hookInfo = startHookServerIfNeeded(hookUrl)
    hookServer = hookInfo["hookServer"]
    effectiveHookUrl = hookInfo["hookUrl"]
    if fflUseStdin:
        args = buildShareArgs(
            "-",
            name,
            e2ee,
            authUser,
            authPassword,
            maxDownloads,
            timeoutSeconds,
            effectiveHookUrl,
            proxy,
        )
        return spawnFflAndWaitLink(args, rawBytes, waitLinkSeconds, tempPaths, hookServer)

    tempPath = createTempFile(name, rawBytes)
    tempPaths.append(tempPath)
    args = buildShareArgs(
        tempPath,
        name,
        e2ee,
        authUser,
        authPassword,
        maxDownloads,
        timeoutSeconds,
        effectiveHookUrl,
        proxy,
    )
    return spawnFflAndWaitLink(args, None, waitLinkSeconds, tempPaths, hookServer)


@mcp.tool
def fflShareFile(
    path: str,
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    waitLinkSeconds: int = defaultWaitLinkSeconds,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Share a local file or folder using ffl. Respects ALLOWED_BASE_DIR when configured.
    """
    sharePath = pathlib.Path(path)
    if not sharePath.exists():
        raise FileNotFoundError(path)
    if not isPathAllowed(sharePath):
        raise PermissionError(f"Path not allowed by ALLOWED_BASE_DIR: {path}")

    hookInfo = startHookServerIfNeeded(hookUrl)
    hookServer = hookInfo["hookServer"]
    effectiveHookUrl = hookInfo["hookUrl"]
    args = buildShareArgs(
        str(sharePath),
        None,
        e2ee,
        authUser,
        authPassword,
        maxDownloads,
        timeoutSeconds,
        effectiveHookUrl,
        proxy,
    )
    return spawnFflAndWaitLink(args, None, waitLinkSeconds, None, hookServer)


@mcp.tool
def fflListSessions() -> List[Dict[str, Any]]:
    """List active ffl share sessions started by this MCP server."""
    return sessionStore.listSessions()


@mcp.tool
def fflStopSession(sessionId: str) -> Dict[str, Any]:
    """Stop a running ffl session by sessionId."""
    return sessionStore.stopSession(sessionId)


@mcp.tool
def fflGetSession(sessionId: str) -> Dict[str, Any]:
    """Get details for a running session."""
    sessionInfo = sessionStore.getSession(sessionId)
    if not sessionInfo:
        return {"ok": False, "error": "not_found"}
    hookServer = sessionInfo.get("hookServer")
    eventCount = hookServer.getEventCount() if hookServer else 0
    return {
        "ok": True,
        "sessionId": sessionId,
        "pid": sessionInfo["process"].pid,
        "link": sessionInfo["link"],
        "ageSeconds": int(time.time() - sessionInfo["startedAt"]),
        "cmd": sessionInfo["command"],
        "eventCount": eventCount,
    }


@mcp.tool
def fflGetSessionEvents(sessionId: str, limit: int = 50) -> Dict[str, Any]:
    """Get recent hook events for a running session."""
    sessionInfo = sessionStore.getSession(sessionId)
    if not sessionInfo:
        return {"ok": False, "error": "not_found"}
    hookServer = sessionInfo.get("hookServer")
    if not hookServer:
        return {"ok": True, "sessionId": sessionId, "events": []}
    return {"ok": True, "sessionId": sessionId, "events": hookServer.getEvents(limit)}


def main() -> None:
    configureLogging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--path", default="/mcp")
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port, path=args.path)


if __name__ == "__main__":
    main()
