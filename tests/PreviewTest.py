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
"""
Tests for src/preview.py and the HookServer preview endpoint mechanism.

  PngEncoderTest            — stdlib PNG encoder produces structurally valid PNG bytes
  ComtypesInterfaceTest     — comtypes COM interface definitions (win32 only)
  GenerateThumbnailTest     — generateThumbnail() public API
  WindowsThumbnailTest      — Windows-specific IShellItemImageFactory path (win32 only)
  WindowsVideoThumbnailTest — Windows video thumbnail via IShellItemImageFactory (win32 only)
  MacThumbnailTest          — macOS Quick Look path (darwin only)
  LinuxThumbnailTest        — Linux ffmpeg/convert path (linux only)
  HookServerPreviewTest     — HookServer /manifest and /thumb endpoint mechanism
"""

import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import zlib
from pathlib import Path
from urllib.parse import urlparse, urlencode
from unittest.mock import patch

# Ensure src/ and tests/ are importable
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import preview as previewMod
import MCP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _makePng(width: int, height: int, color: tuple = (255, 0, 0)) -> bytes:
    """Create a solid-color PNG using our own encoder (no external deps)."""
    r, g, b = color
    rgb = bytes([r, g, b] * width) * height
    return previewMod._encodePng(width, height, rgb)


def _parsePngDimensions(data: bytes):
    """Return (width, height) from PNG IHDR, or raise if not a valid PNG."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Not a PNG")
    # IHDR chunk starts at byte 8: 4-len + 4-type + 13-data
    w, h = struct.unpack(">II", data[16:24])
    return w, h


def _isPng(data: bytes) -> bool:
    return isinstance(data, bytes) and data[:8] == b"\x89PNG\r\n\x1a\n"


def _tempImageFile(suffix: str = ".png", width: int = 64, height: int = 48,
                   color: tuple = (128, 64, 200)) -> str:
    """Write a small solid-color PNG to a temp file and return the path."""
    data = _makePng(width, height, color)
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


# ---------------------------------------------------------------------------
# PNG encoder unit tests
# ---------------------------------------------------------------------------

class PngEncoderTest(unittest.TestCase):
    """Tests for _encodePng — pure stdlib PNG writer."""

    def testPngMagicBytes(self):
        data = _makePng(4, 4)
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")

    def testPngHasIhdrChunk(self):
        data = _makePng(4, 4)
        # IHDR chunk type at bytes 12-16
        self.assertEqual(data[12:16], b"IHDR")

    def testPngDimensions1x1(self):
        data = _makePng(1, 1, (255, 255, 255))
        w, h = _parsePngDimensions(data)
        self.assertEqual(w, 1)
        self.assertEqual(h, 1)

    def testPngDimensions64x48(self):
        data = _makePng(64, 48)
        w, h = _parsePngDimensions(data)
        self.assertEqual(w, 64)
        self.assertEqual(h, 48)

    def testPngHasIdatChunk(self):
        data = _makePng(8, 8)
        self.assertIn(b"IDAT", data)

    def testPngHasIendChunk(self):
        data = _makePng(8, 8)
        self.assertTrue(data.endswith(b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)))

    def testPngIdatDecompressesWithoutError(self):
        data = _makePng(16, 16, (0, 128, 255))
        # Locate IDAT chunk and decompress — verifies pixel data is valid zlib
        idx = data.index(b"IDAT")
        length = struct.unpack(">I", data[idx - 4:idx])[0]
        compressed = data[idx + 4:idx + 4 + length]
        raw = zlib.decompress(compressed)
        # Each row: 1 filter byte + width*3 pixel bytes
        self.assertEqual(len(raw), 16 * (1 + 16 * 3))

    def testPngChunkCrcIsValid(self):
        data = _makePng(4, 4)
        # Verify IHDR chunk CRC
        ihdrLen = struct.unpack(">I", data[8:12])[0]
        ihdrPayload = data[12:12 + 4 + ihdrLen]     # type + data
        expectedCrc = zlib.crc32(ihdrPayload) & 0xFFFFFFFF
        actualCrc   = struct.unpack(">I", data[12 + 4 + ihdrLen:12 + 4 + ihdrLen + 4])[0]
        self.assertEqual(actualCrc, expectedCrc)

    def testPngRgbColorEncoding(self):
        """A 1x1 red pixel PNG must decompress to a red pixel."""
        data = _makePng(1, 1, (255, 0, 0))
        idx = data.index(b"IDAT")
        length = struct.unpack(">I", data[idx - 4:idx])[0]
        raw = zlib.decompress(data[idx + 4:idx + 4 + length])
        # 1 filter byte + 3 RGB bytes
        self.assertEqual(raw[0], 0)      # filter type None
        self.assertEqual(raw[1], 255)    # R
        self.assertEqual(raw[2], 0)      # G
        self.assertEqual(raw[3], 0)      # B

    def testDefaultThumbnailIsPng(self):
        data, mimeType = previewMod.generateDefaultThumbnail()
        self.assertEqual(mimeType, "image/png")
        self.assertTrue(_isPng(data))
        self.assertEqual(_parsePngDimensions(data), (256, 256))


# ---------------------------------------------------------------------------
# comtypes COM interface definitions (Windows only)
# ---------------------------------------------------------------------------

@unittest.skipUnless(sys.platform == "win32", "comtypes is only available on Windows")
class ComtypesInterfaceTest(unittest.TestCase):
    """Verify the comtypes IShellItem / IShellItemImageFactory interface definitions."""

    def testIShellItemIidString(self):
        iid = str(previewMod._IShellItem._iid_)
        self.assertEqual(iid.upper(), "{43826D1E-E718-42EE-BC55-A1E261C37BFE}")

    def testIShellItemImageFactoryIidString(self):
        iid = str(previewMod._IShellItemImageFactory._iid_)
        self.assertEqual(iid.upper(), "{BCC18B79-BA16-442F-80C4-8A59C30C463B}")

    def testIShellItemImageFactoryHasGetImageMethod(self):
        """_IShellItemImageFactory must expose GetImage as a callable method."""
        self.assertTrue(
            hasattr(previewMod._IShellItemImageFactory, "GetImage"),
            "_IShellItemImageFactory missing GetImage — check _methods_ definition",
        )

    def testIShellItemIidsAreDifferent(self):
        self.assertNotEqual(
            str(previewMod._IShellItem._iid_),
            str(previewMod._IShellItemImageFactory._iid_),
        )

    def testSizeStructFields(self):
        """_SIZE must have cx and cy fields."""
        import ctypes
        s = previewMod._SIZE(cx=10, cy=20)
        self.assertEqual(s.cx, 10)
        self.assertEqual(s.cy, 20)


# ---------------------------------------------------------------------------
# generateThumbnail() public API
# ---------------------------------------------------------------------------

class GenerateThumbnailTest(unittest.TestCase):
    """Tests for the public generateThumbnail() function."""

    def testNonExistentFileReturnsNone(self):
        result = previewMod.generateThumbnail("/nonexistent/path/image.png")
        self.assertIsNone(result)

    def testDirectoryReturnsNone(self):
        result = previewMod.generateThumbnail(tempfile.gettempdir())
        self.assertIsNone(result)

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testRealImageFileReturnsTuple(self):
        path = _tempImageFile(width=64, height=48)
        try:
            result = previewMod.generateThumbnail(path)
            self.assertIsNotNone(result, "Expected thumbnail for a valid PNG file")
            data, mime = result
            self.assertIsInstance(data, bytes)
            self.assertGreater(len(data), 0)
            self.assertEqual(mime, "image/png")
        finally:
            os.unlink(path)

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testReturnedDataIsValidPng(self):
        path = _tempImageFile(width=32, height=32, color=(0, 200, 100))
        try:
            result = previewMod.generateThumbnail(path)
            if result is None:
                self.skipTest("Platform thumbnail not available")
            data, _ = result
            self.assertTrue(_isPng(data), "Returned data is not a valid PNG")
        finally:
            os.unlink(path)

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testThumbnailRespectsmaxSize(self):
        path = _tempImageFile(width=512, height=512)
        try:
            result = previewMod.generateThumbnail(path, maxSize=64)
            if result is None:
                self.skipTest("Platform thumbnail not available")
            data, _ = result
            if _isPng(data):
                w, h = _parsePngDimensions(data)
                self.assertLessEqual(w, 64)
                self.assertLessEqual(h, 64)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Windows-specific: IShellItemImageFactory path
# ---------------------------------------------------------------------------

@unittest.skipUnless(sys.platform == "win32", "Windows-only test")
class WindowsThumbnailTest(unittest.TestCase):
    """Tests for _getWindowsThumbnail on Windows."""

    def testPngFileProducesPng(self):
        path = _tempImageFile(suffix=".png", width=64, height=64)
        try:
            data = previewMod._getWindowsThumbnail(path, maxSize=128)
            self.assertIsNotNone(data, "_getWindowsThumbnail returned None for a PNG file")
            self.assertTrue(_isPng(data))
        finally:
            os.unlink(path)

    def testThumbnailDimensionsWithinBounds(self):
        path = _tempImageFile(suffix=".png", width=256, height=256)
        try:
            data = previewMod._getWindowsThumbnail(path, maxSize=128)
            if data is None:
                self.skipTest("Windows thumbnail not available in this environment")
            w, h = _parsePngDimensions(data)
            self.assertLessEqual(w, 128)
            self.assertLessEqual(h, 128)
        finally:
            os.unlink(path)

    def testNonExistentFileReturnsNone(self):
        result = previewMod._getWindowsThumbnail("C:\\nonexistent\\image.png")
        self.assertIsNone(result)

    def testJpegFileProducesPng(self):
        """Windows Shell thumbnails a JPEG file and we return PNG."""
        # Create a PNG but name it .jpg — Shell will still process it
        path = _tempImageFile(suffix=".jpg", width=64, height=64, color=(200, 100, 50))
        try:
            data = previewMod._getWindowsThumbnail(path, maxSize=128)
            if data is None:
                self.skipTest("Windows thumbnail not available in this environment")
            self.assertTrue(_isPng(data))
        finally:
            os.unlink(path)

    def testWindowsSystemImage(self):
        """Try thumbnailing a known Windows system image (present on all installs)."""
        candidates = [
            r"C:\Windows\Web\Wallpaper\Windows\img0.jpg",
            r"C:\Windows\Web\Screen\img100.jpg",
            r"C:\Windows\Web\4K\Wallpaper\Windows\img0_3840x2400.jpg",
        ]
        path = next((p for p in candidates if os.path.isfile(p)), None)
        if path is None:
            self.skipTest("No Windows system wallpaper found")
        data = previewMod._getWindowsThumbnail(path, maxSize=256)
        self.assertIsNotNone(data, f"Expected thumbnail for system image: {path}")
        self.assertTrue(_isPng(data))
        w, h = _parsePngDimensions(data)
        self.assertLessEqual(w, 256)
        self.assertLessEqual(h, 256)

    def testGetWindowsThumbnailFlagsYieldThumbnailNotIcon(self):
        """
        With SIIGBF_THUMBNAILONLY (0x08) the Shell must return an actual thumbnail
        for an image file rather than a generic icon.  We verify the returned PNG
        has non-zero dimensions — if the flags were wrong Windows often returns None
        or a tiny 16x16 icon bitmap.
        """
        path = _tempImageFile(suffix=".png", width=128, height=128)
        try:
            data = previewMod._getWindowsThumbnail(path, maxSize=128)
            if data is None:
                self.skipTest("Windows thumbnail not available in this environment")
            self.assertTrue(_isPng(data))
            w, h = _parsePngDimensions(data)
            self.assertGreater(w, 0)
            self.assertGreater(h, 0)
        finally:
            os.unlink(path)

    def testHbitmapToPngWithSyntheticBitmap(self):
        """
        Verify _hbitmapToPng converts a GDI bitmap to valid PNG bytes.
        Creates a real HBITMAP via GDI32 CreateCompatibleBitmap.
        """
        import ctypes
        gdi32  = ctypes.windll.gdi32
        user32 = ctypes.windll.user32

        hdc = user32.GetDC(None)
        hbmp = gdi32.CreateCompatibleBitmap(hdc, 32, 32)
        user32.ReleaseDC(None, hdc)
        self.assertTrue(hbmp, "CreateCompatibleBitmap failed")

        try:
            data = previewMod._hbitmapToPng(hbmp)
            self.assertIsNotNone(data)
            self.assertTrue(_isPng(data))
            w, h = _parsePngDimensions(data)
            self.assertEqual(w, 32)
            self.assertEqual(h, 32)
        finally:
            gdi32.DeleteObject(ctypes.c_void_p(hbmp))


# ---------------------------------------------------------------------------
# Windows video thumbnail — IShellItemImageFactory + SIIGBF_THUMBNAILONLY
# ---------------------------------------------------------------------------

@unittest.skipUnless(sys.platform == "win32", "Windows-only test")
class WindowsVideoThumbnailTest(unittest.TestCase):
    """
    Tests that video files produce real frame thumbnails on Windows.

    Windows Shell uses registered video thumbnail providers (e.g. the built-in
    MP4/MKV codec thumbnail provider) via IShellItemImageFactory.  The
    SIIGBF_THUMBNAILONLY (0x08) flag is required — without it Windows may fall
    back to a generic codec icon instead of a frame grab.
    """

    @classmethod
    def _findSampleVideo(cls):
        """Return path to a sample video file present on this machine, or None."""
        candidates = [
            # Windows sample videos (present on most Win10/11 installs)
            r"C:\Users\Public\Videos\Sample Videos\Wildlife.wmv",
            r"C:\Windows\Web\Screen\img100.mp4",
        ]
        # Also search user's Videos folder for any mp4/wmv/avi
        import glob as globMod
        userVideos = os.path.expandvars(r"%USERPROFILE%\Videos")
        for pattern in ("*.mp4", "*.wmv", "*.avi", "*.mkv"):
            matches = globMod.glob(os.path.join(userVideos, pattern))
            candidates.extend(matches[:1])
        return next((p for p in candidates if os.path.isfile(p)), None)

    @classmethod
    def _createSyntheticVideo(cls):
        """
        Create a tiny 1-second solid-color MP4 via ffmpeg (if installed).
        Returns the temp file path, or None if ffmpeg is unavailable.
        """
        import shutil as shutilMod
        if not shutilMod.which("ffmpeg"):
            return None
        fd, path = tempfile.mkstemp(suffix=".mp4")
        os.close(fd)
        r = subprocess.run(
            [
                "ffmpeg", "-y", "-f", "lavfi",
                "-i", "color=red:size=64x64:rate=5",
                "-t", "1", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                path,
            ],
            capture_output=True,
            timeout=30,
        )
        if r.returncode == 0 and os.path.getsize(path) > 0:
            return path
        os.unlink(path)
        return None

    def testVideoFileReturnsThumbnail(self):
        """A real video file must produce PNG bytes (not None) on Windows."""
        videoPath = self._findSampleVideo()
        if videoPath is None:
            self.skipTest("No sample video file found on this machine")
        data = previewMod._getWindowsThumbnail(videoPath, maxSize=256)
        self.assertIsNotNone(data, f"Expected thumbnail for video: {videoPath}")
        self.assertTrue(_isPng(data), "Video thumbnail is not a valid PNG")
        w, h = _parsePngDimensions(data)
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)

    def testSyntheticVideoReturnsThumbnailOrSkip(self):
        """
        Create a minimal MP4 via ffmpeg and verify Windows Shell thumbnails it.
        Skips when ffmpeg is not installed or Shell refuses to thumbnail.
        """
        videoPath = self._createSyntheticVideo()
        if videoPath is None:
            self.skipTest("ffmpeg not available — cannot create synthetic video")
        try:
            data = previewMod._getWindowsThumbnail(videoPath, maxSize=128)
            # Windows Shell may decline to thumbnail a freshly-created temp file
            # (no thumbnail provider registered, no thumbnail cached yet).
            # Treat None as a soft skip rather than a hard failure.
            if data is None:
                self.skipTest("Windows Shell declined to thumbnail synthetic MP4 — normal in sandboxed environments")
            self.assertTrue(_isPng(data))
            w, h = _parsePngDimensions(data)
            self.assertGreater(w, 0)
        finally:
            os.unlink(videoPath)

    def testGenerateThumbnailVideoMimeType(self):
        """generateThumbnail() must return 'image/png' mime for any file it thumbnails."""
        videoPath = self._findSampleVideo()
        if videoPath is None:
            self.skipTest("No sample video file found")
        result = previewMod.generateThumbnail(videoPath)
        if result is None:
            self.skipTest("Windows Shell declined to thumbnail the video")
        data, mime = result
        self.assertEqual(mime, "image/png")
        self.assertTrue(_isPng(data))


# ---------------------------------------------------------------------------
# macOS-specific
# ---------------------------------------------------------------------------

@unittest.skipUnless(sys.platform == "darwin", "macOS-only test")
class MacThumbnailTest(unittest.TestCase):
    """Tests for _getMacThumbnail using qlmanage."""

    def testPngFileProducesData(self):
        path = _tempImageFile(suffix=".png", width=64, height=64)
        try:
            data = previewMod._getMacThumbnail(path, maxSize=128)
            self.assertIsNotNone(data, "qlmanage returned None")
            self.assertGreater(len(data), 0)
        finally:
            os.unlink(path)

    def testNonExistentFileReturnsNone(self):
        result = previewMod._getMacThumbnail("/nonexistent/file.png")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Linux-specific
# ---------------------------------------------------------------------------

@unittest.skipUnless(sys.platform not in ("win32", "darwin"), "Linux-only test")
class LinuxThumbnailTest(unittest.TestCase):
    """Tests for _getLinuxThumbnail — skips when no tool is available."""

    @classmethod
    def setUpClass(cls):
        cls.hasFfmpeg = shutil.which("ffmpeg") is not None
        cls.hasConvert = shutil.which("convert") is not None
        cls.hasTool = cls.hasFfmpeg or cls.hasConvert

    def testPngFileProducesDataWhenToolAvailable(self):
        if not self.hasTool:
            self.skipTest("No thumbnail tool (ffmpeg / convert) found")
        path = _tempImageFile(suffix=".png", width=64, height=64)
        try:
            data = previewMod._getLinuxThumbnail(path, maxSize=128)
            self.assertIsNotNone(data)
            self.assertGreater(len(data), 0)
        finally:
            os.unlink(path)

    def testNonExistentFileReturnsNone(self):
        result = previewMod._getLinuxThumbnail("/nonexistent/file.png")
        self.assertIsNone(result)

    def testFfmpegPathUsedWhenAvailable(self):
        """When ffmpeg is installed, _getLinuxThumbnail must use it (primary path)."""
        if not self.hasFfmpeg:
            self.skipTest("ffmpeg not installed")
        path = _tempImageFile(suffix=".png", width=64, height=64)
        try:
            data = previewMod._getLinuxThumbnail(path, maxSize=128)
            self.assertIsNotNone(data, "ffmpeg path returned None for a valid PNG")
            self.assertGreater(len(data), 0)
        finally:
            os.unlink(path)

    def testVideoFileThumbnailWithFfmpeg(self):
        """ffmpeg must produce a thumbnail for a synthetic video file."""
        if not self.hasFfmpeg:
            self.skipTest("ffmpeg not installed")
        fd, videoPath = tempfile.mkstemp(suffix=".mp4")
        os.close(fd)
        try:
            r = subprocess.run(
                [
                    "ffmpeg", "-y", "-f", "lavfi",
                    "-i", "color=blue:size=64x64:rate=5",
                    "-t", "1", "-c:v", "libx264", "-pix_fmt", "yuv420p",
                    videoPath,
                ],
                capture_output=True,
                timeout=30,
            )
            if r.returncode != 0:
                self.skipTest("ffmpeg failed to create synthetic video")
            data = previewMod._getLinuxThumbnail(videoPath, maxSize=128)
            self.assertIsNotNone(data, "Expected thumbnail for synthetic MP4 via ffmpeg")
            self.assertGreater(len(data), 0)
        finally:
            os.unlink(videoPath)


# ---------------------------------------------------------------------------
# HookServer preview endpoint tests
# ---------------------------------------------------------------------------

def _makeManifestItems(sharedRoot: str, fileNames: list) -> list:
    """Build ffl-style manifest items for a list of filenames under sharedRoot."""
    rootName = os.path.basename(os.path.normpath(sharedRoot))
    items = []
    for i, name in enumerate(fileNames):
        arcname = f"{rootName}/{name}"
        filePath = os.path.join(sharedRoot, name)
        size = os.path.getsize(filePath) if os.path.exists(filePath) else 0
        items.append({
            "arcname": arcname,
            "size": size,
            "mtime": int(os.path.getmtime(filePath)) if os.path.exists(filePath) else 0,
            "index": i,
            "isDir": False,
            "data_offset": 0,
        })
    return items


def _hookPost(hookServer: MCP.HookServer, eventName: str, eventData: dict) -> dict:
    """POST a hook event to the HookServer and return the parsed JSON response."""
    host = hookServer.host
    port = hookServer.port
    username = hookServer.username
    password = hookServer.password
    body = json.dumps({"event": eventName, "data": eventData}).encode("utf-8")
    authToken = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(
        f"http://{host}:{port}{hookServer.path}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Authorization": f"Basic {authToken}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _hookGet(hookServer: MCP.HookServer, path: str, query: dict = None) -> urllib.request.addinfourl:
    """GET a path from the HookServer (auth included). Returns the open response."""
    host = hookServer.host
    port = hookServer.port
    username = hookServer.username
    password = hookServer.password
    url = f"http://{host}:{port}{path}"
    if query:
        url += "?" + urlencode(query)
    authToken = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {authToken}"})
    return urllib.request.urlopen(req)


def _hookGetStatus(hookServer: MCP.HookServer, path: str, query: dict = None) -> tuple:
    """GET a path and return (status_code, body_bytes) without raising on error codes."""
    import urllib.error
    try:
        with _hookGet(hookServer, path, query) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class HookServerPreviewTest(unittest.TestCase):
    """Tests for HookServer /manifest and /thumb endpoint mechanism."""

    def setUp(self):
        self.hookServer = MCP.HookServer(
            host="127.0.0.1",
            port=0,
            path="/events",
            username="ffl-mcp",
            password="test-secret",
            maxEvents=100,
        )
        self.hookServer.start()
        # Temp dir with some image files
        self.tmpDir = tempfile.mkdtemp()
        self.imgPaths = []
        for name in ["photo1.png", "photo2.png"]:
            path = os.path.join(self.tmpDir, name)
            data = _makePng(32, 32)
            with open(path, "wb") as f:
                f.write(data)
            self.imgPaths.append(path)

    def tearDown(self):
        self.hookServer.stop()
        for path in self.imgPaths:
            try:
                os.unlink(path)
            except Exception:
                pass
        try:
            os.rmdir(self.tmpDir)
        except Exception:
            pass

    def _postShareLinkCreate(self, filePath, fileNames, link="https://ffl.example.com/abc123"):
        """Helper: send /share/link/create for files in tmpDir and return manifest items."""
        manifestItems = _makeManifestItems(self.tmpDir, fileNames)
        _hookPost(self.hookServer, "/share/link/create", {
            "link": link,
            "filePath": filePath,
            "manifest": manifestItems,
        })
        return manifestItems

    def testEndpointRegisterReturnsRoutes(self):
        """POST /hook/server/endpoints/register must return preview routes."""
        resp = _hookPost(self.hookServer, "/hook/server/endpoints/register", {"uid": "abc123"})
        self.assertIn("routes", resp)
        routes = {r["path"]: r for r in resp["routes"]}
        self.assertIn("/manifest", routes)
        self.assertIn("/file", routes)
        self.assertIn("/thumb", routes)
        # encryptResponse must be True so ffl encrypts for E2EE-enabled sessions
        self.assertTrue(routes["/manifest"].get("encryptResponse"), "/manifest must have encryptResponse=True")
        self.assertTrue(routes["/file"].get("encryptResponse"), "/file must have encryptResponse=True")
        self.assertTrue(routes["/thumb"].get("encryptResponse"), "/thumb must have encryptResponse=True")

    def testManifestEmptyBeforeShareLinkCreate(self):
        """/manifest returns count=0 when no share/link/create event received yet."""
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["entries"], [])

    def testShareLinkCreatePopulatesManifest(self):
        """After /share/link/create, /manifest returns entries for shared files."""
        self._postShareLinkCreate(self.tmpDir, ["photo1.png", "photo2.png"])

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        self.assertEqual(data["count"], 2)
        self.assertEqual(len(data["entries"]), 2)
        names = [e["name"] for e in data["entries"]]
        rootName = os.path.basename(self.tmpDir)
        self.assertIn(f"{rootName}/photo1.png", names)
        self.assertIn(f"{rootName}/photo2.png", names)

    def testManifestEntriesHaveRequiredFields(self):
        """Each manifest entry must have hash, name, size, mtime, mime fields."""
        self._postShareLinkCreate(self.tmpDir, ["photo1.png"])

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        entry = data["entries"][0]
        for field in ("hash", "name", "size", "mtime", "mime", "index"):
            self.assertIn(field, entry, f"Missing field: {field}")
        self.assertIsInstance(entry["hash"], str)
        self.assertEqual(len(entry["hash"]), 64)  # blake2b hex digest_size=32

    def testManifestHashMatchesBlake2b(self):
        """Hash in manifest entry must match blake2b(arcname, digest_size=32)."""
        manifestItems = self._postShareLinkCreate(self.tmpDir, ["photo1.png"])
        arcname = manifestItems[0]["arcname"]

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        expectedHash = hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest()
        self.assertEqual(data["entries"][0]["hash"], expectedHash)

    def testManifestMimeTypeDetected(self):
        """MIME type must be detected from file extension."""
        self._postShareLinkCreate(self.tmpDir, ["photo1.png"])

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        self.assertEqual(data["entries"][0]["mime"], "image/png")

    def testManifestSkipsDirEntries(self):
        """Directory entries in ffl manifest must be excluded from preview entries."""
        rootName = os.path.basename(self.tmpDir)
        manifestItems = [
            {"arcname": f"{rootName}/subdir", "size": 0, "mtime": 0, "index": 0, "isDir": True, "data_offset": 0},
            {"arcname": f"{rootName}/photo1.png", "size": 100, "mtime": 0, "index": 1, "isDir": False, "data_offset": 0},
        ]
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/abc123",
            "filePath": self.tmpDir,
            "manifest": manifestItems,
        })

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        self.assertEqual(data["count"], 1)
        self.assertEqual(data["entries"][0]["name"], f"{rootName}/photo1.png")

    def testThumbMissingHashReturns400(self):
        """/thumb without ?hash= must return 400."""
        status, _ = _hookGetStatus(self.hookServer, "/thumb")
        self.assertEqual(status, 400)

    def testThumbUnknownHashReturns404(self):
        """/thumb?hash=unknownhash must return 404."""
        status, _ = _hookGetStatus(self.hookServer, "/thumb", {"hash": "deadbeef"})
        self.assertEqual(status, 404)

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testThumbReturnsValidPng(self):
        """/thumb?hash=<valid> for a folder share must return PNG bytes."""
        manifestItems = self._postShareLinkCreate(self.tmpDir, ["photo1.png"])
        arcname = manifestItems[0]["arcname"]
        hashValue = hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest()

        with _hookGet(self.hookServer, "/thumb", {"hash": hashValue}) as resp:
            thumbBytes = resp.read()
            contentType = resp.headers.get("Content-Type", "")

        self.assertIn("image/png", contentType)
        self.assertTrue(_isPng(thumbBytes), "Response is not a valid PNG")

    def testThumbFallsBackToDefaultPngWhenGenerationFails(self):
        """/thumb?hash=<valid> must return a default PNG when thumbnail generation fails."""
        manifestItems = self._postShareLinkCreate(self.tmpDir, ["photo1.png"])
        arcname = manifestItems[0]["arcname"]
        hashValue = hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest()

        with patch.object(MCP, "generateThumbnail", return_value=None):
            with _hookGet(self.hookServer, "/thumb", {"hash": hashValue, "w": "420", "h": "320", "fmt": "jpeg"}) as resp:
                thumbBytes = resp.read()
                contentType = resp.headers.get("Content-Type", "")

        self.assertIn("image/png", contentType)
        self.assertTrue(_isPng(thumbBytes))

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testFileEndpointReturnsOriginalFileBytes(self):
        """/file?hash=<valid> must return the original file bytes, not a thumbnail."""
        manifestItems = self._postShareLinkCreate(self.tmpDir, ["photo1.png"])
        arcname = manifestItems[0]["arcname"]
        hashValue = hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest()
        expectedPath = os.path.join(self.tmpDir, "photo1.png")
        with open(expectedPath, "rb") as f:
            expectedBytes = f.read()

        with _hookGet(self.hookServer, "/file", {"hash": hashValue}) as resp:
            fileBytes = resp.read()
            contentType = resp.headers.get("Content-Type", "")

        self.assertIn("image/png", contentType)
        self.assertEqual(fileBytes, expectedBytes)

    @unittest.skipUnless(sys.platform != "linux" or __import__("shutil").which("ffmpeg") or
                         __import__("shutil").which("convert"),
                         "No thumbnail tool available on Linux")
    def testThumbMultipleFilesReturnsValidPng(self):
        """/thumb?hash=<valid> for a multi-file share (filePath as list) must return PNG."""
        filePaths = [p for p in self.imgPaths]
        manifestItems = _makeManifestItems(self.tmpDir, ["photo1.png", "photo2.png"])
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/abc123",
            "filePath": filePaths,
            "manifest": manifestItems,
        })
        arcname = manifestItems[0]["arcname"]
        hashValue = hashlib.blake2b(arcname.encode("utf-8"), digest_size=32).hexdigest()

        with _hookGet(self.hookServer, "/thumb", {"hash": hashValue}) as resp:
            thumbBytes = resp.read()
            contentType = resp.headers.get("Content-Type", "")

        self.assertIn("image/png", contentType)
        self.assertTrue(_isPng(thumbBytes))

    def testMultipleFilesManifest(self):
        """filePath as a list (multi-file share) must produce one entry per file."""
        filePaths = [p for p in self.imgPaths]
        manifestItems = _makeManifestItems(self.tmpDir, ["photo1.png", "photo2.png"])
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/abc123",
            "filePath": filePaths,
            "manifest": manifestItems,
        })

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        self.assertEqual(data["count"], 2)
        names = [os.path.basename(e["name"]) for e in data["entries"]]
        self.assertIn("photo1.png", names)
        self.assertIn("photo2.png", names)

    @unittest.skipUnless(sys.platform == "win32", "Cosmopolitan path conversion is Windows-only")
    def testCosmopolitanPathConversion(self):
        """_toNativePath converts /C/Users/... to C:\\Users\\... on Windows."""
        result = MCP.HookServer._toNativePath("/C/Users/Naga/file.txt")
        self.assertEqual(result, r"C:\Users\Naga\file.txt")

    def testCosmopolitanPathNonWindowsPassthrough(self):
        """_toNativePath returns path unchanged on non-Windows."""
        # On Windows this still tests the positive /C/ case so skip
        if sys.platform == "win32":
            self.skipTest("Use testCosmopolitanPathConversion on Windows")
        result = MCP.HookServer._toNativePath("/home/user/file.txt")
        self.assertEqual(result, "/home/user/file.txt")

    def testManifestUidFromShareLink(self):
        """uid in manifest response must come from the share link path."""
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/myuid123/index.html",
            "filePath": self.tmpDir,
            "manifest": [],
        })

        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())

        self.assertEqual(data["uid"], "myuid123")

    def testGetRequiresAuth(self):
        """/manifest must require Basic Auth — unauthenticated request gets 401."""
        import urllib.error
        host = self.hookServer.host
        port = self.hookServer.port
        req = urllib.request.Request(f"http://{host}:{port}/manifest")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 401)


# ---------------------------------------------------------------------------
# zipSize from /hook/server/endpoints/register context
# ---------------------------------------------------------------------------

class ManifestZipSizeTest(unittest.TestCase):
    """
    Tests that /manifest returns the correct zipSize sourced from the
    fileSize field in the /hook/server/endpoints/register event context
    (= server.reader.size = SegmentIndex.totalSize in ffl).
    """

    def setUp(self):
        self.hookServer = MCP.HookServer(
            host="127.0.0.1", port=0, path="/events",
            username="ffl-mcp", password="test-secret", maxEvents=100,
        )
        self.hookServer.start()

    def tearDown(self):
        self.hookServer.stop()

    def _registerAndShare(self, fileName, fileSize, manifestItems):
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": fileName,
            "fileSize": fileSize,
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/testXYZ",
            "filePath": [f"/C/Users/test/{fileName}"],
            "manifest": manifestItems,
        })

    def testZipSizeFromRegistration(self):
        """zipSize must equal the fileSize from the registration event."""
        self._registerAndShare("archive.zip", 80_000_000, [
            {"arcname": "archive/a.mp4", "size": 50_000_000, "mtime": 0, "index": 0, "isDir": False, "data_offset": 0},
            {"arcname": "archive/b.jpg", "size": 30_000_000, "mtime": 0, "index": 1, "isDir": False, "data_offset": 50_200_000},
        ])
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["zipSize"], 80_000_000)

    def testZipSizeFromEntriesWhenNoRegistration(self):
        """When no registration event fires, zipSize must be estimated from entries' dataOffset+size."""
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/testXYZ",
            "filePath": ["/C/Users/test/a.mp4"],
            "manifest": [
                {"arcname": "archive/a.mp4", "size": 10_000_000, "mtime": 0, "index": 0, "isDir": False, "data_offset": 0},
            ],
        })
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["zipSize"], 10_000_000)

    def testZipNameFromRegistration(self):
        """zipName must use fileName from registration context."""
        self._registerAndShare("my_backup.zip", 1_000_000, [
            {"arcname": "my_backup/a.txt", "size": 100, "mtime": 0, "index": 0, "isDir": False, "data_offset": 0},
        ])
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["zipName"], "my_backup.zip")

    def testRegistrationFileSizeZeroIgnored(self):
        """fileSize=0 in registration must not set _zipSize; fallback estimates from entries."""
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": "archive.zip",
            "fileSize": 0,
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/testXYZ",
            "filePath": ["/C/Users/test/a.mp4"],
            "manifest": [
                {"arcname": "archive/a.mp4", "size": 10_000_000, "mtime": 0, "index": 0, "isDir": False, "data_offset": 0},
            ],
        })
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        # _zipSize stays 0 (fileSize=0 ignored), fallback computes 0+10_000_000
        self.assertEqual(data["zipSize"], 10_000_000)

    def testRegistrationFileSizeNoneIgnored(self):
        """fileSize absent in registration must not crash; fallback estimates from entries."""
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": "archive.zip",
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/testXYZ",
            "filePath": ["/C/Users/test/a.mp4"],
            "manifest": [
                {"arcname": "archive/a.mp4", "size": 10_000_000, "mtime": 0, "index": 0, "isDir": False, "data_offset": 0},
            ],
        })
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        # _zipSize stays 0 (no fileSize in registration), fallback computes 0+10_000_000
        self.assertEqual(data["zipSize"], 10_000_000)

    def testZipSizeFromEntriesWhenRegistrationMissingFileSize(self):
        """When registration has no fileSize, zipSize is estimated from entries' max(dataOffset+size)."""
        # Simulates older ffl binary that omits fileSize from registration context.
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": "archive.zip",
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/testXYZ",
            "filePath": ["/C/Users/test/a.mp4", "/C/Users/test/b.mp4", "/C/Users/test/c.mp4"],
            "manifest": [
                {"arcname": "archive/a.mp4", "size": 119135942, "mtime": 0, "index": 0, "isDir": False, "data_offset": 49},
                {"arcname": "archive/b.mp4", "size": 59796177,  "mtime": 0, "index": 1, "isDir": False, "data_offset": 119135991},
                {"arcname": "archive/c.mp4", "size": 54547672,  "mtime": 0, "index": 2, "isDir": False, "data_offset": 178932168},
            ],
        })
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        # Expected: max(dataOffset) + size = 178932168 + 54547672 = 233479840
        self.assertEqual(data["zipSize"], 233479840)


# ---------------------------------------------------------------------------
# Single-file share: synthetic manifest entry
# ---------------------------------------------------------------------------

class SingleFileManifestTest(unittest.TestCase):
    """
    Tests for single-file shares where ffl uses FileSourceReader
    (supportManifest = False) and emits no manifest in shareLinkCreate.
    The hook server must synthesize one entry from the registration context.
    """

    def setUp(self):
        self.hookServer = MCP.HookServer(
            host="127.0.0.1", port=0, path="/events",
            username="ffl-mcp", password="test-secret", maxEvents=100,
        )
        self.hookServer.start()

    def tearDown(self):
        self.hookServer.stop()

    def _sendSingleFileShare(self, fileName, fileSize, link="https://ffl.example.com/abc123"):
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": fileName,
            "fileSize": fileSize,
        })
        # No 'manifest' key — FileSourceReader doesn't emit entries
        _hookPost(self.hookServer, "/share/link/create", {
            "link": link,
            "filePath": f"/C/Users/test/{fileName}",
        })

    def _sendSingleLocalFileShare(self, path, fileSize=128, link="https://ffl.example.com/abc123"):
        fileName = os.path.basename(path)
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": fileName,
            "fileSize": fileSize,
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": link,
            "filePath": path,
        })

    def testSyntheticEntryCreated(self):
        """Single file with no manifest entries must produce one synthetic entry."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["count"], 1)
        self.assertEqual(len(data["entries"]), 1)

    def testSyntheticEntryName(self):
        """Synthetic entry name must be the registered fileName."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["entries"][0]["name"], "video.mp4")

    def testSyntheticEntrySize(self):
        """Synthetic entry size must equal the registered fileSize."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["entries"][0]["size"], 28_000_000)

    def testSyntheticEntryMime(self):
        """Synthetic entry mime must be detected from the file extension."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["entries"][0]["mime"], "video/mp4")

    def testZipSizeEqualsFileSize(self):
        """zipSize for a single file must equal the registered fileSize."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["zipSize"], 28_000_000)

    def testZipNameIsFilename(self):
        """zipName for a single file must be the actual filename (not a .zip name)."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["zipName"], "video.mp4")

    def testUnicodeFilename(self):
        """Synthetic entry must handle unicode filenames correctly."""
        self._sendSingleFileShare("迷因歌曲-黑雪之歌2.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["entries"][0]["name"], "迷因歌曲-黑雪之歌2.mp4")
        self.assertEqual(data["entries"][0]["mime"], "video/mp4")

    def testHashMatchesBlake2b(self):
        """Synthetic entry hash must match blake2b(fileName, digest_size=32)."""
        self._sendSingleFileShare("video.mp4", 28_000_000)
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        expected = hashlib.blake2b("video.mp4".encode("utf-8"), digest_size=32).hexdigest()
        self.assertEqual(data["entries"][0]["hash"], expected)

    def testSyntheticSingleFileHashResolvesToSharedFile(self):
        """Synthetic single-file manifest hashes must resolve for /file?hash=... previews."""
        with tempfile.TemporaryDirectory() as tmpDir:
            filePath = os.path.join(tmpDir, "single.png")
            with open(filePath, "wb") as f:
                f.write(_makePng(16, 16))
            self._sendSingleLocalFileShare(filePath, os.path.getsize(filePath))
            hashValue = hashlib.blake2b("single.png".encode("utf-8"), digest_size=32).hexdigest()
            resolvedPath = self.hookServer.resolveFileByHash(hashValue)
            self.assertEqual(resolvedPath, filePath)

    def testNoSyntheticEntryWhenFileSizeZero(self):
        """fileSize=0 in registration must not create a synthetic entry."""
        _hookPost(self.hookServer, "/hook/server/endpoints/register", {
            "fileName": "video.mp4",
            "fileSize": 0,
        })
        _hookPost(self.hookServer, "/share/link/create", {
            "link": "https://ffl.example.com/abc123",
            "filePath": "/C/Users/test/video.mp4",
        })
        with _hookGet(self.hookServer, "/manifest") as resp:
            data = json.loads(resp.read())
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["zipSize"], 0)


# ---------------------------------------------------------------------------
# Preview sidecar policy
# ---------------------------------------------------------------------------

class PreviewSidecarPolicyTest(unittest.TestCase):
    """MCP should only create the internal preview sidecar for folder/multi-file shares."""

    def testSingleFileShareDoesNotEnablePreviewSidecarOrPreviewLink(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello")
            filePath = tmp.name
        try:
            with patch.object(MCP, "shareWithFfl", return_value={"link": "https://ffl.example.com/abc"}) as mocked:
                result = MCP.fflShareFile.fn(filePath, preview=True)
        finally:
            os.unlink(filePath)

        self.assertEqual(result["link"], "https://ffl.example.com/abc")
        self.assertFalse(mocked.call_args.kwargs["enablePreviewSidecar"])

    def testFolderShareEnablesPreviewSidecarAndKeepsCleanLink(self):
        with tempfile.TemporaryDirectory() as tmpDir:
            with patch.object(MCP, "shareWithFfl", return_value={"link": "https://ffl.example.com/abc"}) as mocked:
                result = MCP.fflShareFile.fn(tmpDir, preview=True)

        self.assertEqual(result["link"], "https://ffl.example.com/abc")
        self.assertTrue(mocked.call_args.kwargs["enablePreviewSidecar"])

    def testMultiFileShareEnablesPreviewSidecarAndKeepsCleanLink(self):
        with tempfile.TemporaryDirectory() as tmpDir:
            paths = []
            for name in ("a.txt", "b.txt"):
                path = os.path.join(tmpDir, name)
                with open(path, "wb") as f:
                    f.write(b"x")
                paths.append(path)

            with patch.object(MCP, "shareWithFfl", return_value={"link": "https://ffl.example.com/abc"}) as mocked:
                result = MCP.fflShareFiles.fn(paths, preview=True)

        self.assertEqual(result["link"], "https://ffl.example.com/abc")
        self.assertTrue(mocked.call_args.kwargs["enablePreviewSidecar"])


if __name__ == "__main__":
    unittest.main()
