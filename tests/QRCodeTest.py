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
Tests for QR code handling:
  - QRExtractionTest       — ASCII QR block parsing from ffl stdout (unit, no binary)
  - QRCodeIntegrationTest  — qrInTerminal=True round-trip via ffl (needs network)
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import MCP
from IntegrationBase import FflIntegrationBase, callTool, requiresFflBinary, requiresNetwork


class QRExtractionTest(unittest.TestCase):
    """Unit tests for extractQrCodeFromOutput() and isQrOutputLine()."""

    def testIsQRLineWithBlockChars(self):
        self.assertTrue(MCP.isQrOutputLine("█████████████████████████████"))
        self.assertTrue(MCP.isQrOutputLine("▀▄█▀▄█▀▄█▀▄"))

    def testIsQRLineWithMixedBlockChars(self):
        self.assertTrue(MCP.isQrOutputLine("  █ ▄▄▄▄▄ █▀█  "))

    def testIsQRLineReturnsFalseForPlainText(self):
        self.assertFalse(MCP.isQrOutputLine("Starting server..."))
        self.assertFalse(MCP.isQrOutputLine("Link: https://ffl.link/abc"))
        self.assertFalse(MCP.isQrOutputLine(""))

    def testExtractQRFromOutputWithSingleBlock(self):
        output = (
            "Starting ffl...\n"
            "Link: https://ffl.link/abc123\n"
            "█████████████████████████████\n"
            "█ ▄▄▄▄▄ █▀▄██ ▀▀▄▄█ ▄▄▄▄▄ █\n"
            "█ █   █ █▄▀██▄█▀▄██ █   █ █\n"
            "█▄▄▄▄▄▄▄█▄█▄█▄█▄█▄█▄▄▄▄▄▄▄█\n"
            "Session started\n"
        )
        qrCode = MCP.extractQrCodeFromOutput(output)
        self.assertIsNotNone(qrCode)
        self.assertIn("█", qrCode)
        self.assertNotIn("Starting ffl", qrCode)
        self.assertNotIn("Link:", qrCode)
        self.assertNotIn("Session started", qrCode)

    def testExtractQRReturnsNoneForPlainOutput(self):
        output = "Starting ffl...\nLink: https://ffl.link/abc123\nDone\n"
        self.assertIsNone(MCP.extractQrCodeFromOutput(output))

    def testExtractQRReturnsNoneForEmptyString(self):
        self.assertIsNone(MCP.extractQrCodeFromOutput(""))

    def testExtractQRPicksLongestBlock(self):
        output = (
            "▀▄\n"           # short — 1 line
            "Not QR\n"
            "█████\n"
            "▀▄█▀▄\n"        # longer — 3 lines
            "█████\n"
            "Done\n"
        )
        qrCode = MCP.extractQrCodeFromOutput(output)
        self.assertIsNotNone(qrCode)
        self.assertGreater(qrCode.count("\n"), 0)

    def testExtractQRStripsANSIEscapes(self):
        output = "\x1b[32m█████████████████████████████\x1b[0m\n"
        qrCode = MCP.extractQrCodeFromOutput(output)
        self.assertIsNotNone(qrCode)


@requiresFflBinary
@requiresNetwork
class QRCodeIntegrationTest(FflIntegrationBase):
    """Integration tests for qrInTerminal=True — require tunnel establishment."""

    def testShareTextWithQRReturnsQRCode(self):
        result = callTool(MCP.fflShareText,
            text="QR test content",
            name="qr_test.txt",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
            qrInTerminal=True,
        )
        self.assertIn("link", result)
        self.assertIn("qrCode", result)
        self.assertIn("█", result["qrCode"])

    def testQRCodeContainsMultipleLines(self):
        result = callTool(MCP.fflShareText,
            text="Multi-line QR test",
            name="qr_multiline.txt",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
            qrInTerminal=True,
        )
        if "qrCode" in result:
            self.assertGreater(result["qrCode"].count("\n"), 1)

    def testShareFileWithQRReturnsLink(self):
        contentPath = self._makeTempPath(suffix=".txt")
        Path(contentPath).write_text("File QR test", encoding="utf-8")

        result = callTool(MCP.fflShareFile,
            path=contentPath,
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
            qrInTerminal=True,
        )
        self.assertIn("link", result)


if __name__ == "__main__":
    unittest.main()
