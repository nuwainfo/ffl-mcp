import argparse
import base64
import json
import logging
import os
import pathlib
import shlex
import tempfile
import threading
import time
import uuid
import subprocess
from typing import Optional, Dict, Any, List

from fastmcp import FastMCP


logger = logging.getLogger("fflMcp")
logger.setLevel(logging.DEBUG)

mcp = FastMCP("ffl-mcp")

defaultWaitLinkSeconds = int(os.environ.get("FFL_WAIT_LINK_SECONDS", "20"))
allowedBaseDir = os.environ.get("ALLOWED_BASE_DIR")
fflRunMode = os.environ.get("FFL_RUN_MODE", "binary").lower()
fflBin = os.environ.get("FFL_BIN", os.path.join(os.path.dirname(__file__), "ffl.com"))
fflPython = os.environ.get("FFL_PYTHON", "python")
fflCorePath = os.environ.get("FFL_CORE_PATH")
fflCommandOverride = os.environ.get("FFL_COMMAND")
fflUseStdin = os.environ.get("FFL_USE_STDIN", "").lower() in ("1", "true", "yes")


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


def waitForLink(jsonPath: str, waitSeconds: int) -> str:
    deadline = time.time() + max(1, waitSeconds)
    while time.time() < deadline:
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


def spawnFflAndWaitLink(
    fflArgs: List[str],
    stdinBytes: Optional[bytes],
    waitSeconds: int,
    tempPaths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    tempPaths = tempPaths or []
    jsonTemp = tempfile.NamedTemporaryFile(prefix="ffl_", suffix=".json", delete=False)
    jsonPath = jsonTemp.name
    jsonTemp.close()
    tempPaths.append(jsonPath)

    command = buildBaseCommand() + fflArgs + ["--json", jsonPath]
    command_str = " ".join(command)

    logger.info("Starting ffl: %s", command_str)

    process = subprocess.Popen(
        command_str,
        shell=True,
        stdin=subprocess.PIPE if stdinBytes is not None else None,
        #stdout=subprocess.DEVNULL,
        #stderr=subprocess.DEVNULL,
        cwd=os.path.dirname(__file__),
    )

    if stdinBytes is not None and process.stdin is not None:
        process.stdin.write(stdinBytes)
        process.stdin.close()

    link = waitForLink(jsonPath, waitSeconds)

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
    if fflUseStdin:
        args = buildShareArgs("-", name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds, hookUrl, proxy)
        return spawnFflAndWaitLink(args, text.encode("utf-8"), waitLinkSeconds, tempPaths)

    tempPath = createTempFile(name, text.encode("utf-8"))
    tempPaths.append(tempPath)
    args = buildShareArgs(tempPath, name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds, hookUrl, proxy)
    return spawnFflAndWaitLink(args, None, waitLinkSeconds, tempPaths)


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
    if fflUseStdin:
        args = buildShareArgs("-", name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds, hookUrl, proxy)
        return spawnFflAndWaitLink(args, rawBytes, waitLinkSeconds, tempPaths)

    tempPath = createTempFile(name, rawBytes)
    tempPaths.append(tempPath)
    args = buildShareArgs(tempPath, name, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds, hookUrl, proxy)
    return spawnFflAndWaitLink(args, None, waitLinkSeconds, tempPaths)


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

    args = buildShareArgs(str(sharePath), None, e2ee, authUser, authPassword, maxDownloads, timeoutSeconds, hookUrl, proxy)
    return spawnFflAndWaitLink(args, None, waitLinkSeconds)


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
    return {
        "ok": True,
        "sessionId": sessionId,
        "pid": sessionInfo["process"].pid,
        "link": sessionInfo["link"],
        "ageSeconds": int(time.time() - sessionInfo["startedAt"]),
        "cmd": sessionInfo["command"],
    }


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
