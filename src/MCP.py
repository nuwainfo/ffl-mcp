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

import argparse
import base64
import hashlib
import io
import json
import logging
import mimetypes
import os
import pathlib
import re
import sys
import tempfile
import threading
import time
import uuid

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, quote, urlparse

from fastmcp import FastMCP
import ffl

logger = logging.getLogger("fflMcp")
logger.setLevel(logging.DEBUG)

mcp = FastMCP("ffl-mcp")

ansiEscapePattern = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
qrBlockChars = ("█", "▀", "▄")
boxDrawingChars = set("─│┌┐└┘├┤┬┴┼═║╔╗╚╝╠╣╦╩╬")


def stripAnsiSequences(text: str) -> str:
    return ansiEscapePattern.sub("", text)


def isQrOutputLine(line: str) -> bool:
    cleanLine = stripAnsiSequences(line)
    return any(char in cleanLine for char in qrBlockChars)


def isBoxDrawingLine(line: str) -> bool:
    cleanLine = stripAnsiSequences(line).strip()
    if not cleanLine:
        return False

    return all(char in boxDrawingChars for char in cleanLine)


def extractQrCodeFromOutput(output: str) -> Optional[str]:
    lines = output.splitlines()
    if not lines:
        return None

    spans = []
    spanStart = None
    for index, line in enumerate(lines):
        if isQrOutputLine(line):
            if spanStart is None:
                spanStart = index
        elif spanStart is not None:
            spans.append((spanStart, index))
            spanStart = None

    if spanStart is not None:
        spans.append((spanStart, len(lines)))

    if not spans:
        return None

    spanStart, spanEnd = max(spans, key=lambda item: item[1] - item[0])
    qrLines = []
    for line in lines[spanStart:spanEnd]:
        if isBoxDrawingLine(line):
            continue
            
        qrLines.append(line.rstrip("\r"))

    if not qrLines:
        return None

    return "\n".join(qrLines)


allowedBaseDir = os.environ.get("ALLOWED_BASE_DIR")
fflUseStdin = os.environ.get("FFL_USE_STDIN", "").lower() in ("1", "true", "yes")
fflUseHook = os.environ.get("FFL_USE_HOOK", "1").lower() in ("1", "true", "yes")
fflHookHost = os.environ.get("FFL_HOOK_HOST", "127.0.0.1")
fflHookPath = os.environ.get("FFL_HOOK_PATH", "/events")
fflHookUsername = os.environ.get("FFL_HOOK_USERNAME", "ffl-mcp")
fflHookPassword = os.environ.get("FFL_HOOK_PASSWORD")
fflHookMaxEvents = int(os.environ.get("FFL_HOOK_MAX_EVENTS", "200"))


def parseFFLDebug() -> Tuple[bool, Optional[str]]:
    """
    Parse FFL_DEBUG environment variable.
    Returns (enabled, path) tuple.
    - FFL_DEBUG=1 or FFL_DEBUG=true -> (True, None) - use temp file
    - FFL_DEBUG=/path/to/log.txt -> (True, "/path/to/log.txt") - use specific path
    - FFL_DEBUG not set or empty -> (False, None) - disabled
    """
    value = os.environ.get("FFL_DEBUG", "").strip()

    if not value:
        return False, None

    if value.lower() in ("1", "true", "yes"):
        return True, None

    return True, value


fflDebugEnabled, fflDebugPath = parseFFLDebug()


def parseBasicAuthHeader(headerValue: Optional[str]) -> Optional[Dict[str, str]]:
    if not headerValue:
        return None

    if not headerValue.startswith("Basic "):
        return None

    encoded = headerValue[len("Basic "):].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None

    if ":" not in decoded:
        return None

    userName, password = decoded.split(":", 1)
    return {"userName": userName, "password": password}


try:
    from src.Preview import generateDefaultThumbnail, generateThumbnail
except ImportError:
    from Preview import generateDefaultThumbnail, generateThumbnail


class HookRequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        logger.debug("Hook request: %s", format % args)

    def _sendUnauthorized(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ffl-mcp"')
        self.end_headers()

    def _sendError(self, code: int, message: Optional[str] = None) -> None:
        if message is None:
            self.send_response(code)
            self.end_headers()
            return

        self._sendJson(code, {"error": message})

    def _sendHeaders(self, code: int, contentType: str, contentLength: int) -> None:
        self.send_response(code)
        self.send_header("Content-Type", contentType)
        self.send_header("Content-Length", str(contentLength))
        self.end_headers()

    def _sendJson(self, code: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._sendHeaders(code, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _sendBytes(self, mimeType: str, data: bytes) -> None:
        self._sendHeaders(200, mimeType, len(data))
        self.wfile.write(data)

    def _sendFile(self, filePath: str, mimeType: str, fileHandle) -> None:
        self._sendHeaders(200, mimeType, os.path.getsize(filePath))

        while True:
            chunk = fileHandle.read(1024 * 1024)
            if not chunk:
                break
                
            self.wfile.write(chunk)

    def _resolveHashParam(self, hookServer: "HookServer", args: Dict[str, List[str]]) -> Optional[str]:
        hashValue = args.get("hash", [None])[0]
        if not hashValue:
            self._sendError(400)
            return None

        filePath = hookServer.resolveFileByHash(hashValue)
        if not filePath:
            self._sendError(404)
            return None

        return filePath

    def do_POST(self):
        hookServer = self.server
        if not hookServer.isAuthorized(self.headers.get("Authorization")):
            self._sendUnauthorized()
            return

        if hookServer.path and self.path != hookServer.path:
            self._sendError(404)
            return

        contentLength = int(self.headers.get("Content-Length", "0"))
        if contentLength == 0:
            self._sendError(400, "empty body")
            return

        try:
            requestBody = self.rfile.read(contentLength)
            data = json.loads(requestBody.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._sendError(400, f"invalid json: {exc}")
            return

        eventName = data.get("event")
        eventData = data.get("data", {})
        if not eventName:
            self._sendError(400, "missing event")
            return

        try:
            eventResponse = hookServer.handleEvent(eventName, eventData)
        except Exception as exc:
            logger.warning("Hook handler error: %s", exc)
            self._sendError(500, f"handler error: {exc}")
            return

        self._sendJson(200, eventResponse if eventResponse is not None else {"status": "ok"})

    def do_GET(self):
        hookServer = self.server
        if not hookServer.isAuthorized(self.headers.get("Authorization")):
            self._sendUnauthorized()
            return

        parsed = urlparse(self.path)
        args = parse_qs(parsed.query)

        if parsed.path == "/manifest":
            self._sendJson(200, hookServer.getManifestData())
            return

        if parsed.path == "/file":
            filePath = self._resolveHashParam(hookServer, args)
            if not filePath:
                return

            mimeType, _ = mimetypes.guess_type(filePath)
            try:
                with open(filePath, "rb") as fileHandle:
                    self._sendFile(filePath, mimeType or "application/octet-stream", fileHandle)
            except OSError:
                self._sendError(404)
            return

        if parsed.path == "/thumb":
            filePath = self._resolveHashParam(hookServer, args)
            if not filePath:
                return

            thumbBytes, mimeType = generateThumbnail(filePath) or generateDefaultThumbnail()
            self._sendBytes(mimeType, thumbBytes)
            return

        self._sendError(404)


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
        self._manifestEntries: List[Dict[str, Any]] = []
        self._hashToEntry: Dict[str, Dict[str, Any]] = {}
        self._arcnameToPath: Dict[str, str] = {}
        self._sharedRoot: Optional[str] = None
        self._zipSize: Optional[int] = None
        self._registeredFileName: Optional[str] = None
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

    def handleEvent(self, eventName: str, eventData: Any) -> Optional[Dict[str, Any]]:
        entry = {"event": eventName, "data": eventData, "timestamp": time.time()}
        with self._eventLock:
            self._events.append(entry)
            if len(self._events) > self.maxEvents:
                self._events = self._events[-self.maxEvents:]

        if eventName == "/share/link/create" and isinstance(eventData, dict):
            self._storeManifest(eventData)
            return None

        if eventName == "/hook/server/endpoints/register":
            if isinstance(eventData, dict):
                rawFileSize = eventData.get("fileSize")
                rawFileName = eventData.get("fileName")
                with self._eventLock:
                    if isinstance(rawFileSize, (int, float)) and rawFileSize > 0:
                        self._zipSize = int(rawFileSize)
                        
                    if isinstance(rawFileName, str) and rawFileName:
                        self._registeredFileName = rawFileName

            return {
                "routes": [
                    {
                        "method": "GET",
                        "path": "/manifest",
                        "encryptResponse": True
                    },
                    {
                        "method": "GET",
                        "path": "/file",
                        "encryptResponse": True
                    },
                    {
                        "method": "GET",
                        "path": "/thumb",
                        "encryptResponse": True
                    },
                ]
            }

        return None

    @staticmethod
    def _toNativePath(p: str) -> str:
        """Convert a Cosmopolitan /C/Users/... path to C:\\Users\\... on Windows."""
        if sys.platform == "win32" and p.startswith("/") and len(p) >= 3 and p[1].isalpha() and p[2] == "/":
            return p[1].upper() + ":\\" + p[3:].replace("/", "\\")

        return p

    def _storeManifest(self, eventData: Dict[str, Any]) -> None:
        linkValue = eventData.get("link")
        manifestItems = eventData.get("manifest", [])
        rawFilePath = eventData.get("filePath")

        # filePath can be a string (single file/folder) or list (multiple files)
        # Build arcname → native local path lookup for quick resolution
        arcnameToPath: Dict[str, str] = {}
        if isinstance(rawFilePath, list):
            # Multiple files: build basename → native path map
            for p in rawFilePath:
                nativePath = self._toNativePath(p)
                arcnameToPath[os.path.basename(nativePath)] = nativePath
        elif isinstance(rawFilePath, str):
            nativePath = self._toNativePath(rawFilePath)
            rawFilePath = nativePath # normalize for later use

        entries: List[Dict[str, Any]] = []
        hashMap: Dict[str, Dict[str, Any]] = {}
        fileIndex = 0
        for item in manifestItems:
            if item.get("isDir", False):
                continue
                
            arcname = item.get("arcname", "")
            mimeType, _ = mimetypes.guess_type(arcname)
            if not mimeType:
                mimeType = "application/octet-stream"
                
            previewEntry = {
                "index": fileIndex,
                "segmentIndex": item.get("index", 0),
                "name": arcname,
                "hash": hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest(),
                "size": item.get("size", 0),
                "mtime": item.get("mtime", 0),
                "mime": mimeType,
                "dataOffset": item.get("data_offset", 0),
            }
            entries.append(previewEntry)
            hashMap[previewEntry["hash"]] = previewEntry
            fileIndex += 1

        with self._eventLock:
            if isinstance(linkValue, str):
                self._linkValue = linkValue
                
            self._sharedRoot = rawFilePath
            self._arcnameToPath = arcnameToPath
            self._manifestEntries = entries
            self._hashToEntry = hashMap

    def getManifestData(self) -> Dict[str, Any]:
        with self._eventLock:
            entries = list(self._manifestEntries)
            sharedRoot = self._sharedRoot
            linkValue = self._linkValue
            zipSize = self._zipSize or 0
            registeredFileName = self._registeredFileName

        uid = ""
        if linkValue:
            uid = urlparse(linkValue).path.strip("/").split("/")[0]

        if registeredFileName:
            baseName = os.path.basename(registeredFileName)
            zipName = baseName if baseName.lower().endswith(".zip") else baseName + ".zip"
        elif isinstance(sharedRoot, list):
            zipName = "archive.zip"
        elif sharedRoot:
            zipName = os.path.basename(os.path.normpath(sharedRoot)) + ".zip"
        else:
            zipName = "archive.zip"

        # Single file share: ffl doesn't include manifest in the shareLinkCreate event
        # (FileSourceReader.supportManifest = False), so entries will be empty.
        # Synthesize one entry from the registration context so the preview popup
        # shows the correct file name and size.
        if not entries and registeredFileName and zipSize > 0:
            singleName = os.path.basename(registeredFileName)
            singleMime, _ = mimetypes.guess_type(singleName)
            if not singleMime:
                singleMime = "application/octet-stream"
                
            entries = [{
                "index": 0,
                "segmentIndex": 0,
                "name": singleName,
                "hash": hashlib.blake2b(singleName.encode("utf-8"), digest_size=32).hexdigest(),
                "size": zipSize,
                "mtime": 0,
                "mime": singleMime,
                "dataOffset": 0,
            }]
            zipName = singleName # show the real filename, not a .zip name

        # Fallback: estimate zipSize from entries when registration event didn't
        # provide fileSize (older ffl binary). The last entry's dataOffset + size
        # gives the total byte length of the ZIP archive stream.
        if zipSize == 0 and entries:
            lastEntry = max(entries, key=lambda e: e.get("dataOffset", 0))
            estimated = lastEntry.get("dataOffset", 0) + lastEntry.get("size", 0)
            if estimated > 0:
                zipSize = estimated

        return {
            "uid": uid,
            "zipName": zipName,
            "zipSize": zipSize,
            "count": len(entries),
            "entries": entries,
        }

    def resolveFileByHash(self, hashValue: str) -> Optional[str]:
        with self._eventLock:
            entry = self._hashToEntry.get(hashValue)
            sharedRoot = self._sharedRoot
            arcnameToPath = dict(self._arcnameToPath)
            registeredFileName = self._registeredFileName

        if not entry:
            if not registeredFileName:
                return None

            registeredHash = hashlib.blake2b(
                os.path.basename(registeredFileName).encode("utf-8"),
                digest_size=32
            ).hexdigest()
            
            if hashValue != registeredHash:
                return None

            if isinstance(sharedRoot, str) and os.path.isfile(sharedRoot):
                return sharedRoot

            return None

        arcname = entry["name"]

        # Multiple files: arcname is just the filename, look it up in the basename map
        if arcnameToPath:
            basename = os.path.basename(arcname)
            nativePath = arcnameToPath.get(basename) or arcnameToPath.get(arcname)
            if nativePath and os.path.isfile(nativePath):
                return nativePath
                
            return None

        # Single folder: strip folder-name prefix from arcname
        if not sharedRoot or isinstance(sharedRoot, list):
            return None

        sharedRootName = os.path.basename(os.path.normpath(sharedRoot))
        if arcname.startswith(sharedRootName + "/"):
            relativeName = arcname[len(sharedRootName) + 1:]
        else:
            relativeName = arcname
        filePath = os.path.join(sharedRoot, relativeName.replace("/", os.sep))

        if not os.path.isfile(filePath):
            return None

        return filePath

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
            return [{
                "sessionId": sessionId,
                "pid": info["session"].pid,
                "link": info["link"],
                "ageSeconds": int(now - info["startedAt"]),
                "cmd": list(info["session"].argv),
                "eventCount": len(self.getSessionEvents(info, fflHookMaxEvents)),
            } for sessionId, info in self.sessions.items()]

    @staticmethod
    def getSessionEvents(sessionInfo: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
        hookServer = sessionInfo.get("hookServer")
        if hookServer:
            return hookServer.getEvents(limit)

        events = sessionInfo["session"].event_history[-limit:]
        return [{
            "event": event.name,
            "timestamp": event.timestamp,
            "data": dict(event.data),
        } for event in events]

    def getSession(self, sessionId: str) -> Optional[Dict[str, Any]]:
        self.pruneSessions()
        with self.lock:
            return self.sessions.get(sessionId)

    def stopSession(self, sessionId: str) -> Dict[str, Any]:
        sessionInfo = self.getSession(sessionId)
        if not sessionInfo:
            return {"ok": False, "error": "not_found"}

        try:
            sessionInfo["session"].stop()
        except Exception as exc:
            logger.warning("Failed to stop session %s: %s", sessionId, exc)

        self.cleanupSession(sessionId)
        return {"ok": True, "sessionId": sessionId}

    def cleanupSession(self, sessionId: str) -> None:
        with self.lock:
            sessionInfo = self.sessions.pop(sessionId, None)

        if not sessionInfo:
            return

        try:
            sessionInfo["session"].close()
        except Exception as exc:
            logger.debug("Failed to close session %s: %s", sessionId, exc)

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
                sessionId for sessionId, info in self.sessions.items() if not info["session"].running
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


def validateSharePath(sharePath: pathlib.Path) -> None:
    """Shared existence/ALLOWED_BASE_DIR check for fflShareFile and fflShareFiles."""
    if not sharePath.exists():
        raise FileNotFoundError(str(sharePath))

    if not isPathAllowed(sharePath):
        raise PermissionError(f"Path not allowed by ALLOWED_BASE_DIR: {sharePath}")


def applyPreviewFlag(result: Dict[str, Any], preview: bool) -> Dict[str, Any]:
    """
    When preview=True, append ?preview=true to the returned link so ffl's own
    download page opens straight into the full preview view (see ffl's
    static/js/PreviewUI.js, which reads this exact query param) instead of the
    normal floating card. This is independent of the preview-sidecar mechanism
    (enablePreviewSidecar), which always runs for folder/multi-file shares
    regardless of this flag and only provides the manifest/thumbnail data.
    """
    if preview and isinstance(result.get("link"), str):
        result["link"] += "?preview=true"
        
    return result


def writeDebugLog(prefix: str, stdout: str, stderr: str) -> str:
    """
    Write captured ffl stdout/stderr to fflDebugPath, or a new temp file when unset.
    Used when FFL_DEBUG is enabled to surface the ffl-python binding's captured
    output (log_level=DEBUG) for troubleshooting.
    """
    if fflDebugPath:
        logPath = fflDebugPath
        pathlib.Path(logPath).parent.mkdir(parents=True, exist_ok=True)
    else:
        logTemp = tempfile.NamedTemporaryFile(prefix=prefix, suffix=".log", delete=False, mode="w")
        logPath = logTemp.name
        logTemp.close()

    with open(logPath, "w", encoding="utf-8") as handle:
        handle.write(stdout)
        if stderr:
            handle.write("\n--- stderr ---\n")
            handle.write(stderr)

    return logPath


def maybeAttachDebugLog(response: Dict[str, Any], prefix: str, source: Any) -> Dict[str, Any]:
    """
    Add debugLogPath to response when FFL_DEBUG is enabled; otherwise leave it
    untouched. `source` (an ffl-python result/process object) is only read when
    debug is actually on, so callers can pass a test double that doesn't define
    stdout/stderr.
    """
    if fflDebugEnabled:
        response["debugLogPath"] = writeDebugLog(prefix, source.stdout, source.stderr)
        
    return response


def buildFailureResponse(base: Dict[str, Any], exc: Exception, errorPrefix: str, debugPrefix: str) -> Dict[str, Any]:
    """
    Shared failure-response shape for fflDownload/fflKeygen. ffl.APEProcessError
    carries the failed process's captured stdout/stderr (`exc.result`), which is
    worth surfacing as a debug log; other exceptions don't have that to offer.
    """
    response = {**base, "ok": False, "error": f"{errorPrefix}: {exc}"}
    if isinstance(exc, ffl.APEProcessError):
        return maybeAttachDebugLog(response, debugPrefix, exc.result)
        
    return response


def startHookServerIfNeeded(hookUrl: Optional[str], enablePreviewSidecar: bool = False) -> Dict[str, Any]:
    if hookUrl or not fflUseHook:
        return {"hookServer": None, "hookUrl": hookUrl}

    if not enablePreviewSidecar:
        return {"hookServer": None, "hookUrl": None}

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


def shareWithFFL(
    shareTarget: Union[str, List[str]],
    stdinBytes: Optional[bytes],
    tempPaths: List[str],
    name: Optional[str],
    e2ee: bool,
    authUser: Optional[str],
    authPassword: Optional[str],
    maxDownloads: int,
    timeoutSeconds: int,
    hookUrl: Optional[str],
    proxy: Optional[str],
    qrInTerminal: bool,
    exclude: Optional[str] = None,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPublicKey: Optional[str] = None,
    recipientEmail: Optional[str] = None,
    alias: Optional[str] = None,
    receipt: Optional[str] = None,
    receiptConfirm: Optional[str] = None,
    forceRelay: bool = False,
    upload: Optional[str] = None,
    resumeUpload: bool = False,
    vfs: bool = False,
    preferredTunnel: Optional[str] = None,
    port: Optional[int] = None,
    invite: bool = False,
    pause: Optional[int] = None,
    enableReporting: bool = False,
    enablePreviewSidecar: bool = False,
) -> Dict[str, Any]:
    """
    Common sharing logic for all share functions.
    Handles hook server initialization, argument building, and process spawning.
    """
    hookInfo = startHookServerIfNeeded(hookUrl, enablePreviewSidecar=enablePreviewSidecar)
    hookServer = hookInfo["hookServer"]
    effectiveHookUrl = hookInfo["hookUrl"]
    captureHookEvents = fflUseHook and hookServer is None

    try:
        shareOptions = dict(
            name=name,
            e2ee=e2ee,
            auth_user=authUser,
            auth_password=authPassword,
            max_downloads=maxDownloads,
            timeout_seconds=timeoutSeconds,
            hook_url=effectiveHookUrl,
            capture_hook_events=captureHookEvents,
            proxy=proxy,
            exclude=exclude,
            recipient_auth=recipientAuth,
            pickup_code=pickupCode,
            recipient_public_key=recipientPublicKey,
            recipient_email=recipientEmail,
            alias=alias,
            receipt=receipt,
            receipt_confirm=receiptConfirm,
            force_relay=forceRelay,
            upload=upload,
            resume_upload=resumeUpload,
            vfs=vfs,
            preferred_tunnel=preferredTunnel,
            port=port,
            invite=invite,
            pause=pause,
            enable_reporting=enableReporting,
            qr=True if qrInTerminal else None,
            log_level="DEBUG" if fflDebugEnabled else None,
        )
        if stdinBytes is None:
            session = ffl.share(shareTarget, **shareOptions)
        else:
            contentName = shareOptions.pop("name") or "shared.bin"
            if fflUseStdin:
                session = ffl.share_stream(io.BytesIO(stdinBytes), contentName, **shareOptions)
            else:
                session = ffl.share_bytes(stdinBytes, contentName, **shareOptions)
    except Exception:
        if hookServer:
            hookServer.stop()
        raise

    sessionId = str(uuid.uuid4())
    sessionStore.addSession({
        "sessionId": sessionId,
        "session": session,
        "link": session.link,
        "startedAt": time.time(),
        "tempPaths": tempPaths,
        "hookServer": hookServer,
    })

    result = {
        "sessionId": sessionId,
        "link": session.link,
        "pid": session.pid,
        "cmd": list(session.argv),
    }

    if qrInTerminal and isinstance(session.stdout, str):
        qrCode = extractQrCodeFromOutput(session.stdout)
        if qrCode:
            result["qrCode"] = qrCode

    return result


def buildRecipientKwargs(
    recipientAuth: Optional[str],
    pickupCode: Optional[str],
    recipientPublicKey: Optional[str],
    recipientEmail: Optional[str],
    alias: Optional[str],
    receipt: Optional[str],
    receiptConfirm: Optional[str],
    forceRelay: bool,
    port: Optional[int],
    invite: bool,
    enableReporting: bool,
) -> Dict[str, Any]:
    """
    Options shared by every share tool (recipient authentication, delivery
    receipts, and connection/reporting flags) — the exact keyword set
    `shareWithFFL()` expects for these, gathered once so the four `fflShare*`
    tools don't each repeat the same dict literal.
    """
    return dict(
        recipientAuth=recipientAuth,
        pickupCode=pickupCode,
        recipientPublicKey=recipientPublicKey,
        recipientEmail=recipientEmail,
        alias=alias,
        receipt=receipt,
        receiptConfirm=receiptConfirm,
        forceRelay=forceRelay,
        port=port,
        invite=invite,
        enableReporting=enableReporting,
    )


@mcp.tool
def fflShareText(
    text: str,
    name: str = "shared.txt",
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
    qrInTerminal: bool = False,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPublicKey: Optional[str] = None,
    recipientEmail: Optional[str] = None,
    alias: Optional[str] = None,
    receipt: Optional[str] = None,
    receiptConfirm: Optional[str] = None,
    forceRelay: bool = False,
    port: Optional[int] = None,
    invite: bool = False,
    enableReporting: bool = False,
) -> Dict[str, Any]:
    """
    Share text content using ffl. Returns a sessionId and link.
    If qrInTerminal is True, also returns a QR code as ASCII art for terminal display.

    IMPORTANT: Always present the returned link so the user can click it to open in a browser.
    Do not display it as a plain unformatted URL — in some interfaces (such as Claude Dispatch)
    plain URLs are not auto-linked and will not be clickable.

    Args:
        text: Text content to share
        name: Download filename shown to recipient (default: shared.txt)
        e2ee: Enable end-to-end encryption (default: False)
        authUser: HTTP Basic Auth username to protect the link
        authPassword: HTTP Basic Auth password to protect the link
        maxDownloads: Stop serving after N downloads (default: 1)
        timeoutSeconds: Stop serving after N seconds of inactivity (default: 1800)
        hookUrl: Custom webhook URL for events
        proxy: Proxy server URL (e.g. socks5://127.0.0.1:9050)
        qrInTerminal: Return ASCII QR code art for terminal display
        recipientAuth: Recipient authentication mode — pickup (6-digit code), pubkey (RSA challenge), pubkey+pickup (both), email (OTP)
        pickupCode: Specific pickup code to use (default: auto-generated)
        recipientPublicKey: Path to recipient .fflpub public key file for pubkey auth
        recipientEmail: Recipient email(s) for OTP auth, comma-separated
        alias: Custom link alias instead of random UID (requires Standard+ account)
        receipt: Send email notification when recipient downloads (pass email address, or empty string for account email)
        receiptConfirm: Require recipient to confirm before download starts; pass confirmation message or empty string for default
        forceRelay: Disable direct WebRTC; route all traffic through tunnel
        port: Local HTTP server port (default: auto-detect)
        invite: Open invite page in browser with the sharing link
        enableReporting: Enable ffl error reporting for diagnostics (disabled by default)
    """
    textBytes = text.encode("utf-8")
    kwargs = buildRecipientKwargs(
        recipientAuth, pickupCode, recipientPublicKey, recipientEmail, alias,
        receipt, receiptConfirm, forceRelay, port, invite, enableReporting,
    )

    return shareWithFFL(
        "-", textBytes, [], name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds,
        hookUrl, proxy, qrInTerminal, **kwargs
    )


@mcp.tool
def fflShareBase64(
    dataB64: str,
    name: str = "data.bin",
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
    qrInTerminal: bool = False,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPublicKey: Optional[str] = None,
    recipientEmail: Optional[str] = None,
    alias: Optional[str] = None,
    receipt: Optional[str] = None,
    receiptConfirm: Optional[str] = None,
    forceRelay: bool = False,
    port: Optional[int] = None,
    invite: bool = False,
    enableReporting: bool = False,
) -> Dict[str, Any]:
    """
    Share arbitrary binary data (base64-encoded) using ffl. Returns a sessionId and link.
    If qrInTerminal is True, also returns a QR code as ASCII art for terminal display.

    IMPORTANT: Always present the returned link so the user can click it to open in a browser.
    Do not display it as a plain unformatted URL — in some interfaces (such as Claude Dispatch)
    plain URLs are not auto-linked and will not be clickable.

    Args:
        dataB64: Base64-encoded binary data to share
        name: Download filename shown to recipient (default: data.bin)
        e2ee: Enable end-to-end encryption (default: False)
        authUser: HTTP Basic Auth username to protect the link
        authPassword: HTTP Basic Auth password to protect the link
        maxDownloads: Stop serving after N downloads (default: 1)
        timeoutSeconds: Stop serving after N seconds of inactivity (default: 1800)
        hookUrl: Custom webhook URL for events
        proxy: Proxy server URL (e.g. socks5://127.0.0.1:9050)
        qrInTerminal: Return ASCII QR code art for terminal display
        recipientAuth: Recipient authentication mode — pickup (6-digit code), pubkey (RSA challenge), pubkey+pickup (both), email (OTP)
        pickupCode: Specific pickup code to use (default: auto-generated)
        recipientPublicKey: Path to recipient .fflpub public key file for pubkey auth
        recipientEmail: Recipient email(s) for OTP auth, comma-separated
        alias: Custom link alias instead of random UID (requires Standard+ account)
        receipt: Send email notification when recipient downloads (pass email address, or empty string for account email)
        receiptConfirm: Require recipient to confirm before download starts; pass confirmation message or empty string for default
        forceRelay: Disable direct WebRTC; route all traffic through tunnel
        port: Local HTTP server port (default: auto-detect)
        invite: Open invite page in browser with the sharing link
        enableReporting: Enable ffl error reporting for diagnostics (disabled by default)
    """
    rawBytes = base64.b64decode(dataB64, validate=True)
    kwargs = buildRecipientKwargs(
        recipientAuth, pickupCode, recipientPublicKey, recipientEmail, alias,
        receipt, receiptConfirm, forceRelay, port, invite, enableReporting,
    )

    return shareWithFFL(
        "-", rawBytes, [], name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds,
        hookUrl, proxy, qrInTerminal, **kwargs
    )


@mcp.tool
def fflShareFile(
    path: str,
    name: Optional[str] = None,
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
    qrInTerminal: bool = False,
    preview: bool = False,
    exclude: Optional[str] = None,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPublicKey: Optional[str] = None,
    recipientEmail: Optional[str] = None,
    alias: Optional[str] = None,
    receipt: Optional[str] = None,
    receiptConfirm: Optional[str] = None,
    forceRelay: bool = False,
    upload: Optional[str] = None,
    resumeUpload: bool = False,
    vfs: bool = False,
    preferredTunnel: Optional[str] = None,
    port: Optional[int] = None,
    invite: bool = False,
    pause: Optional[int] = None,
    enableReporting: bool = False,
) -> Dict[str, Any]:
    """
    Share a local file or folder using ffl. Respects ALLOWED_BASE_DIR when configured.
    If qrInTerminal is True, also returns a QR code as ASCII art for terminal display.

    IMPORTANT: Always present the returned link so the user can click it to open in a browser.
    Do not display it as a plain unformatted URL — in some interfaces (such as Claude Dispatch)
    plain URLs are not auto-linked and will not be clickable.

    Args:
        path: Path to file or folder to share
        name: Custom download filename shown to recipient
        e2ee: Enable end-to-end encryption (default: False)
        preview: Open recipient's browser directly in preview mode — ideal for folders or multiple files so the recipient sees a file list before downloading (default: False)
        authUser: HTTP Basic Auth username to protect the link
        authPassword: HTTP Basic Auth password to protect the link
        maxDownloads: Stop serving after N downloads, P2P only (default: 1)
        timeoutSeconds: Stop serving after N seconds of inactivity, P2P only (default: 1800)
        hookUrl: Custom webhook URL for events
        proxy: Proxy server URL (e.g. socks5://127.0.0.1:9050)
        qrInTerminal: Return ASCII QR code art for terminal display
        exclude: Exclude files matching glob or regex patterns, comma-separated (e.g. '*.log' or 're:\\.tmp$')
        recipientAuth: Recipient authentication mode — pickup (6-digit code), pubkey (RSA challenge), pubkey+pickup (both), email (OTP)
        pickupCode: Specific pickup code to use (default: auto-generated)
        recipientPublicKey: Path to recipient .fflpub public key file for pubkey auth
        recipientEmail: Recipient email(s) for OTP auth, comma-separated
        alias: Custom link alias instead of random UID (requires Standard+ account)
        receipt: Send email notification when recipient downloads (pass email address, or empty string for account email)
        receiptConfirm: Require recipient to confirm before download starts; pass confirmation message or empty string for default
        forceRelay: Disable direct WebRTC; route all traffic through tunnel
        upload: Upload to FFL server for async sharing — recipient doesn't need sender online. Pass duration e.g. '1 day', '6 hours', '1 week' (requires Standard+ account)
        resumeUpload: Resume an interrupted upload (default: False)
        vfs: Expose as VFS server (vfs:// URI) instead of regular download
        preferredTunnel: Set preferred tunnel for this and future runs — cloudflare, ngrok, bore, etc.
    """
    sharePath = pathlib.Path(path)
    validateSharePath(sharePath)

    tempPaths: List[str] = []
    kwargs = buildRecipientKwargs(
        recipientAuth, pickupCode, recipientPublicKey, recipientEmail, alias,
        receipt, receiptConfirm, forceRelay, port, invite, enableReporting,
    )

    result = shareWithFFL(
        str(sharePath), None, tempPaths, name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds,
        hookUrl, proxy, qrInTerminal,
        exclude=exclude,
        upload=upload,
        resumeUpload=resumeUpload,
        vfs=vfs,
        preferredTunnel=preferredTunnel,
        pause=pause,
        enablePreviewSidecar=sharePath.is_dir(),
        **kwargs,
    )

    return applyPreviewFlag(result, preview)


@mcp.tool
def fflShareFiles(
    paths: List[str],
    name: Optional[str] = None,
    e2ee: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    maxDownloads: int = 1,
    timeoutSeconds: int = 1800,
    hookUrl: Optional[str] = None,
    proxy: Optional[str] = None,
    qrInTerminal: bool = False,
    preview: bool = False,
    exclude: Optional[str] = None,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPublicKey: Optional[str] = None,
    recipientEmail: Optional[str] = None,
    alias: Optional[str] = None,
    receipt: Optional[str] = None,
    receiptConfirm: Optional[str] = None,
    forceRelay: bool = False,
    upload: Optional[str] = None,
    resumeUpload: bool = False,
    preferredTunnel: Optional[str] = None,
    port: Optional[int] = None,
    invite: bool = False,
    pause: Optional[int] = None,
    enableReporting: bool = False,
) -> Dict[str, Any]:
    """
    Share multiple local files at once using ffl. ffl auto-zips them into a single download.

    IMPORTANT: Always present the returned link so the user can click it to open in a browser.
    Do not display it as a plain unformatted URL — in some interfaces (such as Claude Dispatch)
    plain URLs are not auto-linked and will not be clickable.

    Args:
        paths: List of local file paths to share together (auto-zipped by ffl)
        name: Custom download filename shown to recipient (e.g. 'release-v2.0.zip')
        e2ee: Enable end-to-end encryption (default: False)
        preview: Open recipient's browser directly in preview mode — shows a file list before downloading (default: False). Recommended when sharing multiple files so the recipient can inspect contents first.
        authUser: HTTP Basic Auth username to protect the link
        authPassword: HTTP Basic Auth password to protect the link
        maxDownloads: Stop serving after N downloads, P2P only (default: 1)
        timeoutSeconds: Stop serving after N seconds of inactivity, P2P only (default: 1800)
        hookUrl: Custom webhook URL for events
        proxy: Proxy server URL (e.g. socks5://127.0.0.1:9050)
        qrInTerminal: Return ASCII QR code art for terminal display
        exclude: Exclude files matching glob or regex patterns, comma-separated
        recipientAuth: Recipient authentication mode — pickup, pubkey, pubkey+pickup, email
        pickupCode: Specific pickup code to use (default: auto-generated)
        recipientPublicKey: Path to recipient .fflpub public key file for pubkey auth
        recipientEmail: Recipient email(s) for OTP auth, comma-separated
        alias: Custom link alias instead of random UID (requires Standard+ account)
        receipt: Send email notification when recipient downloads
        receiptConfirm: Require recipient to confirm before download starts
        forceRelay: Disable direct WebRTC; route all traffic through tunnel
        upload: Upload to FFL server for async sharing — e.g. '1 day', '6 hours' (requires Standard+ account)
        resumeUpload: Resume an interrupted upload (default: False)
        preferredTunnel: Set preferred tunnel — cloudflare, ngrok, bore, etc.
    """
    if not paths:
        raise ValueError("paths must contain at least one file path")

    sharePaths = [pathlib.Path(p) for p in paths]
    for sharePath in sharePaths:
        validateSharePath(sharePath)

    shareTargets = [str(p) for p in sharePaths]
    kwargs = buildRecipientKwargs(
        recipientAuth, pickupCode, recipientPublicKey, recipientEmail, alias,
        receipt, receiptConfirm, forceRelay, port, invite, enableReporting,
    )

    result = shareWithFFL(
        shareTargets, None, [], name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds,
        hookUrl, proxy, qrInTerminal,
        exclude=exclude,
        upload=upload,
        resumeUpload=resumeUpload,
        preferredTunnel=preferredTunnel,
        pause=pause,
        enablePreviewSidecar=True,
        **kwargs,
    )

    return applyPreviewFlag(result, preview)


@mcp.tool
def fflDownload(
    url: str,
    outputPath: Optional[str] = None,
    resume: bool = False,
    authUser: Optional[str] = None,
    authPassword: Optional[str] = None,
    proxy: Optional[str] = None,
    recipientAuth: Optional[str] = None,
    pickupCode: Optional[str] = None,
    recipientPrivateKey: Optional[str] = None,
    enableReporting: bool = False,
) -> Dict[str, Any]:
    """
    Download a file from a FastFileLink URL or regular HTTP(S) URL using ffl.

    For FastFileLink URLs, this uses WebRTC P2P when possible for faster downloads.
    For regular URLs, it works like wget.

    Args:
        url: FastFileLink URL or regular HTTP(S) URL to download from
        outputPath: Optional output file or directory path (default: use filename from server)
        resume: Resume incomplete download (default: False)
        authUser: Username for HTTP Basic Authentication
        authPassword: Password for HTTP Basic Authentication
        proxy: Proxy server URL (e.g. socks5://127.0.0.1:9050)
        recipientAuth: Recipient authentication mode required by sender — pickup, pubkey, or email
        pickupCode: 6-digit pickup code (when recipientAuth is pickup)
        recipientPrivateKey: Path to .fflkey private key file for pubkey auth

    Returns:
        Dictionary with download status and output file path
    """
    try:
        downloadResult = ffl.download(
            url,
            output_path=outputPath,
            resume=resume,
            auth_user=authUser,
            auth_password=authPassword,
            proxy=proxy,
            recipient_auth=recipientAuth,
            pickup_code=pickupCode,
            recipient_private_key=recipientPrivateKey,
            enable_reporting=enableReporting,
            log_level="DEBUG" if fflDebugEnabled else None,
        )
    except Exception as exc:
        return buildFailureResponse({"url": url}, exc, "Download failed", "ffl_download_")

    response = {
        "ok": downloadResult.return_code == 0,
        "returncode": downloadResult.return_code,
        "url": url,
        "transferMode": downloadResult.transfer_mode.name.lower(),
    }
    if downloadResult.output_path is not None:
        response["outputPath"] = str(downloadResult.output_path)

    return maybeAttachDebugLog(response, "ffl_download_", downloadResult)


@mcp.tool
def fflKeygen(
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate an RSA keypair for passwordless pubkey authentication.

    Produces two files:
    - <name>.fflpub — public key (share with the sender)
    - <name>.fflkey — private key (keep secret; used during download)

    The sender then shares with: fflShareFile(..., recipientAuth='pubkey', recipientPublicKey='alice.fflpub')
    The recipient downloads with: fflDownload(..., recipientAuth='pubkey', recipientPrivateKey='alice.fflkey')

    Args:
        name: Base name for the generated key files (default: ffl assigns a name)

    Returns:
        Dictionary with returncode and output describing the generated key paths
    """
    try:
        keygenResult = ffl.keygen(
            name,
            enable_reporting=False,
            log_level="DEBUG" if fflDebugEnabled else None,
        )
    except Exception as exc:
        return buildFailureResponse({}, exc, "Key generation failed", "ffl_keygen_")

    response = {
        "ok": keygenResult.return_code == 0,
        "returncode": keygenResult.return_code,
        "privateKeyPath": str(keygenResult.private_key_path),
        "publicKeyPath": str(keygenResult.public_key_path),
        "output": keygenResult.stdout.strip(),
    }

    return maybeAttachDebugLog(response, "ffl_keygen_", keygenResult)


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

    eventCount = len(sessionStore.getSessionEvents(sessionInfo, fflHookMaxEvents))
    return {
        "ok": True,
        "sessionId": sessionId,
        "pid": sessionInfo["session"].pid,
        "link": sessionInfo["link"],
        "ageSeconds": int(time.time() - sessionInfo["startedAt"]),
        "cmd": list(sessionInfo["session"].argv),
        "eventCount": eventCount,
    }


@mcp.tool
def fflGetSessionEvents(sessionId: str, limit: int = 50) -> Dict[str, Any]:
    """Get recent hook events for a running session."""
    sessionInfo = sessionStore.getSession(sessionId)
    if not sessionInfo:
        return {"ok": False, "error": "not_found"}

    events = sessionStore.getSessionEvents(sessionInfo, limit)
    return {"ok": True, "sessionId": sessionId, "events": events}


def main() -> None:
    os.environ.setdefault("FASTMCP_SHOW_CLI_BANNER", "false")
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--path", default="/mcp")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable ffl debug logging: passes --log-level DEBUG to ffl and saves output to a log file. "
        "Equivalent to setting FFL_DEBUG=1.",
    )
    args = parser.parse_args()

    if args.debug:
        os.environ.setdefault("FFL_DEBUG", "1")
        global fflDebugEnabled, fflDebugPath
        fflDebugEnabled, fflDebugPath = parseFFLDebug()

    configureLogging()

    if args.transport == "stdio":
        mcp.run(show_banner=False)
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port, path=args.path, show_banner=False)


if __name__ == "__main__":
    main()
