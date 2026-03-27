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
"""Tests for WSL environment detection — isRunningInWSL() and checkWSLInteropIssue()."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class WSLDetectionTest(unittest.TestCase):

    def testIsRunningInWSLReturnsBool(self):
        self.assertIsInstance(MCP.isRunningInWSL(), bool)

    def testCheckWSLInteropIssueReturnsNoneWhenNotWSL(self):
        with patch.object(MCP, "isRunningInWSL", return_value=False):
            self.assertIsNone(MCP.checkWSLInteropIssue())

    def testCheckWSLInteropIssueReturnsStringWhenWSLDetected(self):
        # On Windows /proc/sys/fs/binfmt_misc/WSLInterop doesn't exist,
        # so the function falls through to the general WSL guidance message.
        with patch.object(MCP, "isRunningInWSL", return_value=True):
            result = MCP.checkWSLInteropIssue()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def testCheckWSLInteropIssueMessageMentionsWSL(self):
        with patch.object(MCP, "isRunningInWSL", return_value=True):
            result = MCP.checkWSLInteropIssue()
        self.assertIn("WSL", result)

    def testCheckWSLInteropIssueMessageContainsFixCommand(self):
        with patch.object(MCP, "isRunningInWSL", return_value=True):
            result = MCP.checkWSLInteropIssue()
        self.assertIn("echo -1", result)


if __name__ == "__main__":
    unittest.main()
