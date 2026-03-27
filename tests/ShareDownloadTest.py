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
Integration tests for ffl share and download operations — require network.

Run with:  FFL_INTEGRATION_TESTS=1 python -m unittest tests/ShareDownloadTest.py -v
"""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import MCP
from IntegrationBase import FflIntegrationBase, callTool, requiresFflBinary, requiresNetwork


@requiresFflBinary
@requiresNetwork
class ShareTextTest(FflIntegrationBase):

    def testShareTextReturnsHttpLink(self):
        result = callTool(MCP.fflShareText,
            text="Hello from integration test",
            name="test.txt",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
        )
        self.assertIn("sessionId", result)
        self.assertIn("link", result)
        self.assertTrue(result["link"].startswith("http"))

    def testShareTextWithBasicAuth(self):
        result = callTool(MCP.fflShareText,
            text="Protected content",
            name="protected.txt",
            e2ee=False,
            authUser="testuser",
            authPassword="testpass",
            maxDownloads=1,
            timeoutSeconds=60,
        )
        self.assertIn("link", result)
        self.assertTrue(result["link"].startswith("http"))

    def testShareTextWithE2EE(self):
        result = callTool(MCP.fflShareText,
            text="Encrypted content",
            name="encrypted.txt",
            e2ee=True,
            maxDownloads=1,
            timeoutSeconds=60,
        )
        self.assertIn("link", result)

    def testShareTextSessionIsTracked(self):
        result = callTool(MCP.fflShareText,
            text="Session tracking test",
            name="session.txt",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
        )
        sessionIds = [s["sessionId"] for s in MCP.sessionStore.listSessions()]
        self.assertIn(result["sessionId"], sessionIds)

    def testShareBase64ReturnsLink(self):
        content = b"Binary content \x00\x01\x02\x03"
        result = callTool(MCP.fflShareBase64,
            dataB64=base64.b64encode(content).decode("utf-8"),
            name="test.bin",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
        )
        self.assertIn("link", result)
        self.assertTrue(result["link"].startswith("http"))


@requiresFflBinary
@requiresNetwork
class ShareFilesTest(FflIntegrationBase):

    def testShareMultipleFilesReturnsLink(self):
        pathA = self._makeTempPath(suffix=".txt")
        pathB = self._makeTempPath(suffix=".csv")
        Path(pathA).write_text("file A content", encoding="utf-8")
        Path(pathB).write_text("col1,col2\n1,2", encoding="utf-8")

        result = callTool(MCP.fflShareFiles,
            paths=[pathA, pathB],
            name="bundle.zip",
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
        )
        self.assertIn("sessionId", result)
        self.assertIn("link", result)
        self.assertTrue(result["link"].startswith("http"))

    def testShareMultipleFilesWithQR(self):
        pathA = self._makeTempPath(suffix=".txt")
        pathB = self._makeTempPath(suffix=".txt")
        Path(pathA).write_text("file A", encoding="utf-8")
        Path(pathB).write_text("file B", encoding="utf-8")

        result = callTool(MCP.fflShareFiles,
            paths=[pathA, pathB],
            e2ee=False,
            maxDownloads=1,
            timeoutSeconds=60,
            qrInTerminal=True,
        )
        self.assertIn("link", result)


@requiresFflBinary
@requiresNetwork
class ShareAndDownloadTest(FflIntegrationBase):

    def testShareAndDownloadTextContent(self):
        testContent = b"Integration test content for download verification."
        downloadPath = self._makeTempPath(suffix=".txt")

        shareResult = callTool(MCP.fflShareText,
            text=testContent.decode("utf-8"),
            name="test_download.txt",
            e2ee=False,
            maxDownloads=2,
            timeoutSeconds=120,
        )
        self.assertIn("link", shareResult)

        downloadResult = callTool(MCP.fflDownload, url=shareResult["link"], outputPath=downloadPath)
        self.assertTrue(downloadResult.get("ok"), f"Download failed: {downloadResult.get('error')}")
        self.assertTrue(Path(downloadPath).exists(), "Downloaded file not found")

        with open(downloadPath, "rb") as f:
            self.assertEqual(f.read(), testContent)

    def testDownloadReportsTransferMode(self):
        shareResult = callTool(MCP.fflShareText,
            text="Transfer mode test",
            name="transfer_mode.txt",
            e2ee=False,
            maxDownloads=2,
            timeoutSeconds=120,
        )
        downloadPath = self._makeTempPath(suffix=".txt")

        downloadResult = callTool(MCP.fflDownload, url=shareResult["link"], outputPath=downloadPath)
        self.assertIn("transferMode", downloadResult)
        self.assertIn(
            downloadResult["transferMode"],
            ("webrtc_p2p", "http_fallback", "http_direct", "unknown"),
        )

    def testDownloadReportsOutputPath(self):
        shareResult = callTool(MCP.fflShareText,
            text="Output path test",
            name="output_path.txt",
            e2ee=False,
            maxDownloads=2,
            timeoutSeconds=120,
        )
        downloadPath = self._makeTempPath(suffix=".txt")

        downloadResult = callTool(MCP.fflDownload, url=shareResult["link"], outputPath=downloadPath)
        if downloadResult.get("ok"):
            self.assertIn("outputPath", downloadResult)


if __name__ == "__main__":
    unittest.main()
