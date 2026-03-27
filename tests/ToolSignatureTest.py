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
"""Tests that verify the MCP tool functions expose the expected parameter API."""

import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class ToolSignatureTest(unittest.TestCase):

    def _params(self, tool):
        fn = tool.fn if hasattr(tool, "fn") else tool
        return inspect.signature(fn).parameters

    # --- fflShareText ---

    def testFflShareTextHasQrInTerminal(self):
        self.assertIn("qrInTerminal", self._params(MCP.fflShareText))

    def testFflShareTextHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareText))

    def testFflShareTextHasPickupCode(self):
        self.assertIn("pickupCode", self._params(MCP.fflShareText))

    def testFflShareTextHasRecipientPublicKey(self):
        self.assertIn("recipientPublicKey", self._params(MCP.fflShareText))

    def testFflShareTextHasRecipientEmail(self):
        self.assertIn("recipientEmail", self._params(MCP.fflShareText))

    def testFflShareTextHasAlias(self):
        self.assertIn("alias", self._params(MCP.fflShareText))

    def testFflShareTextHasReceipt(self):
        self.assertIn("receipt", self._params(MCP.fflShareText))

    def testFflShareTextHasReceiptConfirm(self):
        self.assertIn("receiptConfirm", self._params(MCP.fflShareText))

    def testFflShareTextHasForceRelay(self):
        self.assertIn("forceRelay", self._params(MCP.fflShareText))

    # --- fflShareBase64 ---

    def testFflShareBase64HasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareBase64))

    def testFflShareBase64HasForceRelay(self):
        self.assertIn("forceRelay", self._params(MCP.fflShareBase64))

    # --- fflShareFile ---

    def testFflShareFileHasName(self):
        self.assertIn("name", self._params(MCP.fflShareFile))

    def testFflShareFileHasExclude(self):
        self.assertIn("exclude", self._params(MCP.fflShareFile))

    def testFflShareFileHasUpload(self):
        self.assertIn("upload", self._params(MCP.fflShareFile))

    def testFflShareFileHasResumeUpload(self):
        self.assertIn("resumeUpload", self._params(MCP.fflShareFile))

    def testFflShareFileHasVFS(self):
        self.assertIn("vfs", self._params(MCP.fflShareFile))

    def testFflShareFileHasPreferredTunnel(self):
        self.assertIn("preferredTunnel", self._params(MCP.fflShareFile))

    def testFflShareFileHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareFile))

    # --- fflDownload ---

    def testFflDownloadHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflDownload))

    def testFflDownloadHasPickupCode(self):
        self.assertIn("pickupCode", self._params(MCP.fflDownload))

    def testFflDownloadHasRecipientPrivateKey(self):
        self.assertIn("recipientPrivateKey", self._params(MCP.fflDownload))

    # --- fflShareFiles ---

    def testFflShareFilesExists(self):
        self.assertTrue(hasattr(MCP, "fflShareFiles"))

    def testFflShareFilesHasPathsParam(self):
        self.assertIn("paths", self._params(MCP.fflShareFiles))

    def testFflShareFilesHasName(self):
        self.assertIn("name", self._params(MCP.fflShareFiles))

    def testFflShareFilesHasE2EE(self):
        self.assertIn("e2ee", self._params(MCP.fflShareFiles))

    def testFflShareFilesHasUpload(self):
        self.assertIn("upload", self._params(MCP.fflShareFiles))

    def testFflShareFilesHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareFiles))

    def testFflShareFilesHasExclude(self):
        self.assertIn("exclude", self._params(MCP.fflShareFiles))

    # --- fflKeygen ---

    def testFflKeygenExists(self):
        self.assertTrue(hasattr(MCP, "fflKeygen"))

    def testFflKeygenHasNameParam(self):
        self.assertIn("name", self._params(MCP.fflKeygen))


if __name__ == "__main__":
    unittest.main()
