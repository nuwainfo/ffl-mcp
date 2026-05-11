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
"""Tests for buildShareArgs() — verifies every CLI flag is constructed correctly."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class BuildShareArgsTest(unittest.TestCase):

    def _build(self, **overrides):
        defaults = dict(
            shareTarget="file.txt",
            name=None,
            e2ee=False,
            authUser=None,
            authPassword=None,
            maxDownloads=1,
            timeoutSeconds=30,
            hookUrl=None,
            proxy=None,
        )
        defaults.update(overrides)
        return MCP.buildShareArgs(**defaults)

    # --- basic structure ---

    def testFirstArgIsShareTarget(self):
        args = self._build(shareTarget="myfile.txt")
        self.assertEqual(args[0], "myfile.txt")

    def testMultipleFilesAsListPrefixArgs(self):
        files = ["report.pdf", "data.csv", "readme.md"]
        args = self._build(shareTarget=files)
        self.assertEqual(args[0], "report.pdf")
        self.assertEqual(args[1], "data.csv")
        self.assertEqual(args[2], "readme.md")

    def testMultipleFilesOptionsFollowAfterPaths(self):
        files = ["a.zip", "b.zip"]
        args = self._build(shareTarget=files, name="bundle.zip")
        # Both paths come before any option flags
        nameIdx = args.index("--name")
        self.assertGreater(nameIdx, args.index("b.zip"))

    def testSingleStringAndSingleElementListProduceSameArgs(self):
        argsFromStr = self._build(shareTarget="file.txt")
        argsFromList = self._build(shareTarget=["file.txt"])
        self.assertEqual(argsFromStr, argsFromList)

    def testP2PFlagsIncludedByDefault(self):
        args = self._build(maxDownloads=3, timeoutSeconds=600)
        self.assertIn("--max-downloads", args)
        self.assertEqual(args[args.index("--max-downloads") + 1], "3")
        self.assertIn("--timeout", args)
        self.assertEqual(args[args.index("--timeout") + 1], "600")

    def testNameFlagIncludedWhenSet(self):
        args = self._build(name="output.txt")
        self.assertIn("--name", args)
        self.assertEqual(args[args.index("--name") + 1], "output.txt")

    def testNameFlagOmittedWhenNone(self):
        args = self._build(name=None)
        self.assertNotIn("--name", args)

    # --- encryption ---

    def testE2EEFlagIncludedWhenEnabled(self):
        args = self._build(e2ee=True)
        self.assertIn("--e2ee", args)

    def testE2EEFlagOmittedWhenDisabled(self):
        args = self._build(e2ee=False)
        self.assertNotIn("--e2ee", args)

    # --- upload mode ---

    def testUploadFlagAndValue(self):
        args = self._build(upload="1 day")
        self.assertIn("--upload", args)
        self.assertEqual(args[args.index("--upload") + 1], "1 day")

    def testUploadSkipsP2POnlyFlags(self):
        args = self._build(upload="6 hours")
        self.assertNotIn("--max-downloads", args)
        self.assertNotIn("--timeout", args)

    def testUploadWithResumeFlag(self):
        args = self._build(upload="1 week", resumeUpload=True)
        self.assertIn("--upload", args)
        self.assertIn("--resume", args)

    def testUploadWithPauseFlag(self):
        args = self._build(upload="24 hours", pause=50)
        self.assertIn("--pause", args)
        self.assertEqual(args[args.index("--pause") + 1], "50")

    def testResumeWithoutUpload(self):
        args = self._build(resumeUpload=True)
        self.assertIn("--resume", args)

    # --- recipient authentication ---

    def testRecipientAuthPickup(self):
        args = self._build(recipientAuth="pickup", pickupCode="482910")
        self.assertIn("--recipient-auth", args)
        self.assertEqual(args[args.index("--recipient-auth") + 1], "pickup")
        self.assertIn("--pickup-code", args)
        self.assertEqual(args[args.index("--pickup-code") + 1], "482910")

    def testRecipientAuthPubkey(self):
        args = self._build(recipientAuth="pubkey", recipientPublicKey="/path/alice.fflpub")
        self.assertIn("--recipient-auth", args)
        self.assertEqual(args[args.index("--recipient-auth") + 1], "pubkey")
        self.assertIn("--recipient-public-key", args)
        self.assertEqual(args[args.index("--recipient-public-key") + 1], "/path/alice.fflpub")

    def testRecipientAuthEmail(self):
        args = self._build(recipientAuth="email", recipientEmail="alice@example.com,bob@example.com")
        self.assertIn("--recipient-auth", args)
        self.assertIn("--recipient-email", args)
        self.assertEqual(args[args.index("--recipient-email") + 1], "alice@example.com,bob@example.com")

    def testRecipientAuthPubkeyPlusPickup(self):
        args = self._build(recipientAuth="pubkey+pickup")
        self.assertIn("--recipient-auth", args)
        self.assertEqual(args[args.index("--recipient-auth") + 1], "pubkey+pickup")

    # --- alias ---

    def testAliasFlag(self):
        args = self._build(alias="my-release")
        self.assertIn("--alias", args)
        self.assertEqual(args[args.index("--alias") + 1], "my-release")

    # --- receipt ---

    def testReceiptWithEmail(self):
        args = self._build(receipt="me@example.com")
        self.assertIn("--receipt", args)
        self.assertEqual(args[args.index("--receipt") + 1], "me@example.com")

    def testReceiptEmptyStringAddsFlag(self):
        args = self._build(receipt="")
        self.assertIn("--receipt", args)

    def testReceiptNoneOmitsFlag(self):
        args = self._build(receipt=None)
        self.assertNotIn("--receipt", args)

    def testReceiptConfirmWithMessage(self):
        args = self._build(receiptConfirm="Please confirm you got this")
        self.assertIn("--receipt-confirm", args)
        self.assertEqual(args[args.index("--receipt-confirm") + 1], "Please confirm you got this")

    def testReceiptConfirmEmptyStringAddsFlag(self):
        args = self._build(receiptConfirm="")
        self.assertIn("--receipt-confirm", args)

    def testReceiptConfirmNoneOmitsFlag(self):
        args = self._build(receiptConfirm=None)
        self.assertNotIn("--receipt-confirm", args)

    # --- relay / vfs / tunnel ---

    def testForceRelayFlag(self):
        args = self._build(forceRelay=True)
        self.assertIn("--force-relay", args)

    def testForceRelayOmittedByDefault(self):
        args = self._build(forceRelay=False)
        self.assertNotIn("--force-relay", args)

    def testExcludeFlag(self):
        args = self._build(exclude="*.pyc,__pycache__")
        self.assertIn("--exclude", args)
        self.assertEqual(args[args.index("--exclude") + 1], "*.pyc,__pycache__")

    def testVFSFlag(self):
        args = self._build(vfs=True)
        self.assertIn("--vfs", args)

    def testVFSOmittedByDefault(self):
        args = self._build(vfs=False)
        self.assertNotIn("--vfs", args)

    def testPreferredTunnelFlag(self):
        args = self._build(preferredTunnel="cloudflare")
        self.assertIn("--preferred-tunnel", args)
        self.assertEqual(args[args.index("--preferred-tunnel") + 1], "cloudflare")

    def testPortFlag(self):
        args = self._build(port=8080)
        self.assertIn("--port", args)
        self.assertEqual(args[args.index("--port") + 1], "8080")

    def testInviteFlag(self):
        args = self._build(invite=True)
        self.assertIn("--invite", args)

    def testEnableReportingFlag(self):
        args = self._build(enableReporting=True)
        self.assertIn("--enable-reporting", args)

    # --- access control ---

    def testAuthUserAndPassword(self):
        args = self._build(authUser="alice", authPassword="s3cr3t")
        self.assertIn("--auth-user", args)
        self.assertEqual(args[args.index("--auth-user") + 1], "alice")
        self.assertIn("--auth-password", args)
        self.assertEqual(args[args.index("--auth-password") + 1], "s3cr3t")

    def testProxyFlag(self):
        args = self._build(proxy="socks5://127.0.0.1:9050")
        self.assertIn("--proxy", args)
        self.assertEqual(args[args.index("--proxy") + 1], "socks5://127.0.0.1:9050")

    def testHookUrl(self):
        hookUrl = "http://ffl-mcp:pass@127.0.0.1:54321/events"
        args = self._build(hookUrl=hookUrl)
        self.assertIn("--hook", args)
        self.assertEqual(args[args.index("--hook") + 1], hookUrl)

    def testHookAppearsBeforeProxy(self):
        args = self._build(
            hookUrl="http://user:pass@127.0.0.1:1234/events",
            proxy="socks5://127.0.0.1:9050",
        )
        self.assertLess(args.index("--hook"), args.index("--proxy"))

    # --- debug ---

    def testDebugAddsLogLevel(self):
        with patch.object(MCP, "fflDebugEnabled", True):
            args = self._build()
        self.assertIn("--log-level", args)
        self.assertEqual(args[args.index("--log-level") + 1], "DEBUG")

    def testNoDebugByDefault(self):
        with patch.object(MCP, "fflDebugEnabled", False):
            args = self._build()
        self.assertNotIn("--log-level", args)


if __name__ == "__main__":
    unittest.main()
