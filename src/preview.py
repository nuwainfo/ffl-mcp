#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
"""
Platform-native thumbnail generation for ffl-mcp.

No PIL, wx, or ffmpeg required.

Windows : Shell IShellItemImageFactory via comtypes COM.
          Handles images, videos, PDFs, Office docs — anything Windows can thumbnail.
          HBITMAP is decoded with GDI32 GetDIBits and encoded as PNG using stdlib zlib.

macOS   : qlmanage subprocess (Quick Look, built-in on every Mac).

Linux   : ffmpeg subprocess (if installed), then ImageMagick convert (if installed).
          Returns None silently when neither is available.
"""

import ctypes
import logging
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from typing import Optional, Tuple

logger = logging.getLogger("fflMcp.preview")

THUMB_MAX = 256  # default max width/height in pixels


# ---------------------------------------------------------------------------
# Minimal PNG encoder — stdlib only (struct + zlib)
# ---------------------------------------------------------------------------

def _pngChunk(tag: bytes, data: bytes) -> bytes:
    payload = tag + data
    return struct.pack(">I", len(data)) + payload + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)


def _encodePng(width: int, height: int, rgbRows: bytes) -> bytes:
    """Encode raw top-down RGB24 pixel data as PNG bytes."""
    stride = width * 3
    raw = b"".join(b"\x00" + rgbRows[y * stride:(y + 1) * stride] for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _pngChunk(b"IHDR", ihdr)
        + _pngChunk(b"IDAT", zlib.compress(raw, 6))
        + _pngChunk(b"IEND", b"")
    )


# ---------------------------------------------------------------------------
# Windows — IShellItemImageFactory via comtypes
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import comtypes
    from comtypes import GUID, IUnknown, HRESULT, COMMETHOD

    class _SIZE(ctypes.Structure):
        _fields_ = [("cx", ctypes.c_long), ("cy", ctypes.c_long)]

    class _IShellItem(IUnknown):
        _iid_ = GUID("{43826D1E-E718-42EE-BC55-A1E261C37BFE}")
        _methods_ = []

    class _IShellItemImageFactory(IUnknown):
        _iid_ = GUID("{BCC18B79-BA16-442F-80C4-8A59C30C463B}")
        _methods_ = [
            COMMETHOD([], HRESULT, "GetImage",
                      (["in"], _SIZE, "size"),
                      (["in"], ctypes.c_uint32, "flags"),
                      (["out"], ctypes.POINTER(ctypes.c_void_p), "phbm")),
        ]


def _hbitmapToPng(hbitmapInt: int) -> Optional[bytes]:
    """Convert a Windows HBITMAP handle to PNG bytes via GDI32 GetDIBits."""
    gdi32 = ctypes.windll.gdi32
    user32 = ctypes.windll.user32

    class _BITMAP(ctypes.Structure):
        _fields_ = [
            ("bmType", ctypes.c_long),
            ("bmWidth", ctypes.c_long),
            ("bmHeight", ctypes.c_long),
            ("bmWidthBytes", ctypes.c_long),
            ("bmPlanes", ctypes.c_ushort),
            ("bmBitsPixel", ctypes.c_ushort),
            ("bmBits", ctypes.c_void_p),
        ]

    class _BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", ctypes.c_uint32),
            ("biWidth", ctypes.c_int32),
            ("biHeight", ctypes.c_int32),
            ("biPlanes", ctypes.c_uint16),
            ("biBitCount", ctypes.c_uint16),
            ("biCompression", ctypes.c_uint32),
            ("biSizeImage", ctypes.c_uint32),
            ("biXPelsPerMeter", ctypes.c_int32),
            ("biYPelsPerMeter", ctypes.c_int32),
            ("biClrUsed", ctypes.c_uint32),
            ("biClrImportant", ctypes.c_uint32),
        ]

    bm = _BITMAP()
    gdi32.GetObjectW(ctypes.c_void_p(hbitmapInt), ctypes.sizeof(_BITMAP), ctypes.byref(bm))
    width, height = bm.bmWidth, abs(bm.bmHeight)
    if width <= 0 or height <= 0:
        logger.debug("[Preview] HBITMAP has zero dimensions")
        return None

    bih = _BITMAPINFOHEADER()
    bih.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
    bih.biWidth = width
    bih.biHeight = -height   # negative = top-down scanlines
    bih.biPlanes = 1
    bih.biBitCount = 24
    bih.biCompression = 0    # BI_RGB

    stride = (width * 3 + 3) & ~3
    buf = (ctypes.c_ubyte * (stride * height))()

    hdc = user32.GetDC(None)
    try:
        rows = gdi32.GetDIBits(hdc, ctypes.c_void_p(hbitmapInt), 0, height, buf, ctypes.byref(bih), 0)
    finally:
        user32.ReleaseDC(None, hdc)

    if not rows:
        logger.debug("[Preview] GetDIBits returned 0 rows")
        return None

    # GDI delivers BGR24 with per-row padding — convert to tightly-packed RGB24
    rgb = bytearray(width * height * 3)
    pos = 0
    for y in range(height):
        base = y * stride
        for x in range(width):
            rgb[pos]     = buf[base + x * 3 + 2]   # R
            rgb[pos + 1] = buf[base + x * 3 + 1]   # G
            rgb[pos + 2] = buf[base + x * 3]        # B
            pos += 3

    return _encodePng(width, height, bytes(rgb))


def _getWindowsThumbnail(filePath: str, maxSize: int = THUMB_MAX) -> Optional[bytes]:
    """
    Generate thumbnail via Windows Shell IShellItemImageFactory (comtypes COM).

    Works for any file type Windows can thumbnail: images, videos, PDFs, Office docs, etc.
    Returns PNG bytes, or None on failure.
    """
    shell32 = ctypes.windll.shell32
    gdi32 = ctypes.windll.gdi32
    ole32 = ctypes.windll.ole32

    shell32.SHCreateItemFromParsingName.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(comtypes.GUID),
        ctypes.POINTER(ctypes.POINTER(_IShellItem)),
    ]
    shell32.SHCreateItemFromParsingName.restype = ctypes.c_long

    ole32.CoInitializeEx(None, 0x0)
    hbitmapVal = 0

    try:
        pItem = ctypes.POINTER(_IShellItem)()
        hr = shell32.SHCreateItemFromParsingName(
            filePath, None, ctypes.byref(_IShellItem._iid_), ctypes.byref(pItem)
        )
        if hr != 0 or not pItem:
            logger.debug(f"[Preview] SHCreateItemFromParsingName hr=0x{hr & 0xFFFFFFFF:08X}")
            return None

        pFactory = pItem.QueryInterface(_IShellItemImageFactory)
        # SIIGBF_THUMBNAILONLY (0x08) | SIIGBF_SCALEUP (0x100) — request actual
        # thumbnail frame (not a file icon), scale up if smaller than requested size.
        # Required for video files to get a frame grab instead of the codec icon.
        hbitmapVal = pFactory.GetImage(_SIZE(maxSize, maxSize), 0x08 | 0x100) or 0
        if not hbitmapVal:
            logger.debug("[Preview] GetImage returned null HBITMAP")
            return None

        return _hbitmapToPng(hbitmapVal)

    except Exception as e:
        logger.debug(f"[Preview] Windows thumbnail error: {e}")
        return None

    finally:
        if hbitmapVal:
            gdi32.DeleteObject(ctypes.c_void_p(hbitmapVal))
        ole32.CoUninitialize()


# ---------------------------------------------------------------------------
# macOS — Quick Look via qlmanage subprocess
# ---------------------------------------------------------------------------

def _getMacThumbnail(filePath: str, maxSize: int = THUMB_MAX) -> Optional[bytes]:
    """
    Generate thumbnail via macOS Quick Look (qlmanage, built-in).
    Returns PNG bytes, or None on failure.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpDir:
            result = subprocess.run(
                ["qlmanage", "-t", "-s", str(maxSize), "-o", tmpDir, filePath],
                capture_output=True,
                timeout=10,
            )
            for name in sorted(os.listdir(tmpDir)):
                if name.lower().endswith((".png", ".jpg", ".jpeg")):
                    with open(os.path.join(tmpDir, name), "rb") as f:
                        return f.read()
    except Exception as e:
        logger.debug(f"[Preview] qlmanage failed: {e}")
    return None


# ---------------------------------------------------------------------------
# Linux — ffmpegthumbnailer or ImageMagick convert
# ---------------------------------------------------------------------------

def _getLinuxThumbnail(filePath: str, maxSize: int = THUMB_MAX) -> Optional[bytes]:
    """
    Generate thumbnail on Linux.
    Tries ffmpeg first (handles images + videos), then ImageMagick convert.
    Returns PNG bytes, or None when neither tool is available.
    """
    try:
        if shutil.which("ffmpeg"):
            # Seek to 0.1s so video files yield a frame instead of a blank first frame.
            # -vframes 1 stops after one frame; pipe:1 writes PNG to stdout.
            r = subprocess.run(
                [
                    "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
                    "-ss", "0.1", "-i", filePath,
                    "-frames:v", "1",
                    "-vf", f"scale={maxSize}:{maxSize}:force_original_aspect_ratio=decrease",
                    "-f", "image2pipe", "-vcodec", "png", "pipe:1",
                ],
                capture_output=True,
                timeout=15,
            )
            if r.returncode == 0 and r.stdout:
                return r.stdout
    except Exception as e:
        logger.debug(f"[Preview] ffmpeg thumbnail failed: {e}")

    tmpFd, tmpPath = tempfile.mkstemp(suffix=".png")
    os.close(tmpFd)
    try:
        if shutil.which("convert"):
            r = subprocess.run(
                ["convert", filePath + "[0]",
                 "-thumbnail", f"{maxSize}x{maxSize}>",
                 "-background", "white", "-alpha", "remove",
                 tmpPath],
                capture_output=True,
                timeout=15,
            )
            if r.returncode == 0 and os.path.getsize(tmpPath) > 0:
                with open(tmpPath, "rb") as f:
                    return f.read()
    except Exception as e:
        logger.debug(f"[Preview] convert thumbnail failed: {e}")
    finally:
        try:
            os.unlink(tmpPath)
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generateThumbnail(filePath: str, maxSize: int = THUMB_MAX) -> Optional[Tuple[bytes, str]]:
    """
    Generate a thumbnail for any file using platform-native tools only.
    No PIL, wx, or ffmpeg dependency required.

    Platform support:
      Windows : IShellItemImageFactory via comtypes (images, videos, PDFs, Office docs, ...)
      macOS   : qlmanage Quick Look (built-in)
      Linux   : ffmpegthumbnailer or ImageMagick convert (optional, skips if absent)

    Args:
        filePath: Absolute path to the source file.
        maxSize:  Maximum width/height in pixels (default 256).

    Returns:
        (imageBytes, mimeType) tuple, or None if unsupported / generation failed.
        mimeType is 'image/png' for all platforms except macOS where it matches
        whatever qlmanage produced.
    """
    if not os.path.isfile(filePath):
        return None

    if sys.platform == "win32":
        data = _getWindowsThumbnail(filePath, maxSize)
        mime = "image/png"
    elif sys.platform == "darwin":
        data = _getMacThumbnail(filePath, maxSize)
        mime = "image/png"
    else:
        data = _getLinuxThumbnail(filePath, maxSize)
        mime = "image/png"

    if data:
        return data, mime
    return None
