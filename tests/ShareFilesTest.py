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
Tests for fflShareFiles() — multiple-file sharing.

  - ShareFilesValidationTest  — path validation logic (unit, no binary)
  - ShareFilesArgsTest        — verifies multi-file paths are passed as leading positional args
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import MCP
from IntegrationBase import callTool


class ShareFilesValidationTest(unittest.TestCase):

    def testRaisesOnEmptyPathsList(self):
        with self.assertRaises(ValueError):
            callTool(MCP.fflShareFiles, paths=[])

    def testRaisesFileNotFoundForMissingFile(self):
        with self.assertRaises(FileNotFoundError):
            callTool(MCP.fflShareFiles, paths=["/nonexistent/file.txt"])

    def testRaisesFileNotFoundIfAnyFileMissing(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            existingPath = f.name

        try:
            with self.assertRaises(FileNotFoundError):
                callTool(MCP.fflShareFiles, paths=[existingPath, "/nonexistent/other.txt"])
        finally:
            Path(existingPath).unlink(missing_ok=True)

    def testRaisesPermissionErrorWhenOutsideBaseDir(self):
        with tempfile.TemporaryDirectory() as allowedDir:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
                outsidePath = f.name

            try:
                with patch.object(MCP, "allowedBaseDir", allowedDir):
                    with self.assertRaises(PermissionError):
                        callTool(MCP.fflShareFiles, paths=[outsidePath])
            finally:
                Path(outsidePath).unlink(missing_ok=True)


class ShareFilesArgsTest(unittest.TestCase):
    """Verify that multi-file paths become leading positional args in buildShareArgs."""

    def testMultiplePathsPrefixArgs(self):
        files = ["report.pdf", "data.csv", "notes.txt"]
        args = MCP.buildShareArgs(
            shareTarget=files,
            name=None,
            e2ee=False,
            authUser=None,
            authPassword=None,
            maxDownloads=1,
            timeoutSeconds=30,
            hookUrl=None,
            proxy=None,
        )
        self.assertEqual(args[0], "report.pdf")
        self.assertEqual(args[1], "data.csv")
        self.assertEqual(args[2], "notes.txt")

    def testOptionsAppendAfterAllPaths(self):
        files = ["a.zip", "b.zip"]
        args = MCP.buildShareArgs(
            shareTarget=files,
            name="bundle.zip",
            e2ee=True,
            authUser=None,
            authPassword=None,
            maxDownloads=1,
            timeoutSeconds=30,
            hookUrl=None,
            proxy=None,
        )
        lastPathIdx = args.index("b.zip")
        nameIdx = args.index("--name")
        e2eeIdx = args.index("--e2ee")
        self.assertGreater(nameIdx, lastPathIdx)
        self.assertGreater(e2eeIdx, lastPathIdx)

    def testSingleStringAndSingleElementListProduceSameArgs(self):
        kwargs = dict(
            name=None, e2ee=True, authUser=None, authPassword=None,
            maxDownloads=1, timeoutSeconds=30, hookUrl=None, proxy=None,
        )
        argsFromStr = MCP.buildShareArgs(shareTarget="file.txt", **kwargs)
        argsFromList = MCP.buildShareArgs(shareTarget=["file.txt"], **kwargs)
        self.assertEqual(argsFromStr, argsFromList)


if __name__ == "__main__":
    unittest.main()
