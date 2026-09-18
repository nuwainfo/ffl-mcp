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

    def testFFLShareTextHasQrInTerminal(self):
        self.assertIn("qrInTerminal", self._params(MCP.fflShareText))

    def testFFLShareTextHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareText))

    def testFFLShareTextHasPickupCode(self):
        self.assertIn("pickupCode", self._params(MCP.fflShareText))

    def testFFLShareTextHasRecipientPublicKey(self):
        self.assertIn("recipientPublicKey", self._params(MCP.fflShareText))

    def testFFLShareTextHasRecipientEmail(self):
        self.assertIn("recipientEmail", self._params(MCP.fflShareText))

    def testFFLShareTextHasAlias(self):
        self.assertIn("alias", self._params(MCP.fflShareText))

    def testFFLShareTextHasReceipt(self):
        self.assertIn("receipt", self._params(MCP.fflShareText))

    def testFFLShareTextHasReceiptConfirm(self):
        self.assertIn("receiptConfirm", self._params(MCP.fflShareText))

    def testFFLShareTextHasForceRelay(self):
        self.assertIn("forceRelay", self._params(MCP.fflShareText))

    def testFFLShareTextHasPort(self):
        self.assertIn("port", self._params(MCP.fflShareText))

    def testFFLShareTextHasInvite(self):
        self.assertIn("invite", self._params(MCP.fflShareText))

    def testFFLShareTextHasEnableReporting(self):
        self.assertIn("enableReporting", self._params(MCP.fflShareText))

    # --- fflShareBase64 ---

    def testFFLShareBase64HasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareBase64))

    def testFFLShareBase64HasForceRelay(self):
        self.assertIn("forceRelay", self._params(MCP.fflShareBase64))

    def testFFLShareBase64HasPort(self):
        self.assertIn("port", self._params(MCP.fflShareBase64))

    def testFFLShareBase64HasInvite(self):
        self.assertIn("invite", self._params(MCP.fflShareBase64))

    def testFFLShareBase64HasEnableReporting(self):
        self.assertIn("enableReporting", self._params(MCP.fflShareBase64))

    # --- fflShareFile ---

    def testFFLShareFileHasName(self):
        self.assertIn("name", self._params(MCP.fflShareFile))

    def testFFLShareFileHasExclude(self):
        self.assertIn("exclude", self._params(MCP.fflShareFile))

    def testFFLShareFileHasUpload(self):
        self.assertIn("upload", self._params(MCP.fflShareFile))

    def testFFLShareFileHasResumeUpload(self):
        self.assertIn("resumeUpload", self._params(MCP.fflShareFile))

    def testFFLShareFileHasVFS(self):
        self.assertIn("vfs", self._params(MCP.fflShareFile))

    def testFFLShareFileHasPreferredTunnel(self):
        self.assertIn("preferredTunnel", self._params(MCP.fflShareFile))

    def testFFLShareFileHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareFile))

    def testFFLShareFileHasPort(self):
        self.assertIn("port", self._params(MCP.fflShareFile))

    def testFFLShareFileHasInvite(self):
        self.assertIn("invite", self._params(MCP.fflShareFile))

    def testFFLShareFileHasPause(self):
        self.assertIn("pause", self._params(MCP.fflShareFile))

    def testFFLShareFileHasEnableReporting(self):
        self.assertIn("enableReporting", self._params(MCP.fflShareFile))

    # --- fflDownload ---

    def testFFLDownloadHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflDownload))

    def testFFLDownloadHasPickupCode(self):
        self.assertIn("pickupCode", self._params(MCP.fflDownload))

    def testFFLDownloadHasRecipientPrivateKey(self):
        self.assertIn("recipientPrivateKey", self._params(MCP.fflDownload))

    def testFFLDownloadHasEnableReporting(self):
        self.assertIn("enableReporting", self._params(MCP.fflDownload))

    # --- fflShareFiles ---

    def testFFLShareFilesExists(self):
        self.assertTrue(hasattr(MCP, "fflShareFiles"))

    def testFFLShareFilesHasPathsParam(self):
        self.assertIn("paths", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasName(self):
        self.assertIn("name", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasE2EE(self):
        self.assertIn("e2ee", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasUpload(self):
        self.assertIn("upload", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasRecipientAuth(self):
        self.assertIn("recipientAuth", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasExclude(self):
        self.assertIn("exclude", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasPort(self):
        self.assertIn("port", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasInvite(self):
        self.assertIn("invite", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasPause(self):
        self.assertIn("pause", self._params(MCP.fflShareFiles))

    def testFFLShareFilesHasEnableReporting(self):
        self.assertIn("enableReporting", self._params(MCP.fflShareFiles))

    # --- fflKeygen ---

    def testFFLKeygenExists(self):
        self.assertTrue(hasattr(MCP, "fflKeygen"))

    def testFFLKeygenHasNameParam(self):
        self.assertIn("name", self._params(MCP.fflKeygen))


if __name__ == "__main__":
    unittest.main()
