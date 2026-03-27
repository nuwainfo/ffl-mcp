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
Tests for environment variable / config parsing:
  - ParseFflDebugTest  — FFL_DEBUG path and flag parsing
  - ShellModeTest      — shouldUseShell() platform detection
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class ParseFflDebugTest(unittest.TestCase):

    def testDisabledWhenEmpty(self):
        with patch.dict(os.environ, {"FFL_DEBUG": ""}):
            enabled, path = MCP.parseFflDebug()
        self.assertFalse(enabled)
        self.assertIsNone(path)

    def testDisabledWhenNotSet(self):
        env = {k: v for k, v in os.environ.items() if k != "FFL_DEBUG"}
        with patch.dict(os.environ, env, clear=True):
            enabled, path = MCP.parseFflDebug()
        self.assertFalse(enabled)
        self.assertIsNone(path)

    def testEnabledWithOne(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "1"}):
            enabled, path = MCP.parseFflDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testEnabledWithTrue(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "true"}):
            enabled, path = MCP.parseFflDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testEnabledWithYes(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "yes"}):
            enabled, path = MCP.parseFflDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testCustomWindowsPath(self):
        with patch.dict(os.environ, {"FFL_DEBUG": r"D:\mcp.log"}):
            enabled, path = MCP.parseFflDebug()
        self.assertTrue(enabled)
        self.assertEqual(path, r"D:\mcp.log")

    def testCustomUnixPath(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "/tmp/ffl_debug.log"}):
            enabled, path = MCP.parseFflDebug()
        self.assertTrue(enabled)
        self.assertEqual(path, "/tmp/ffl_debug.log")


class ShellModeTest(unittest.TestCase):

    def testEmptyCommandReturnsFalse(self):
        self.assertFalse(MCP.shouldUseShell([]))

    def testOnWindowsComFilesDoNotUseShell(self):
        with patch("platform.system", return_value="Windows"):
            self.assertFalse(MCP.shouldUseShell([r"C:\tools\ffl.com", "--version"]))

    def testOnLinuxComFilesUseShell(self):
        with patch("platform.system", return_value="Linux"):
            with patch.object(MCP, "fflShellMode", False):
                self.assertTrue(MCP.shouldUseShell(["/usr/local/bin/ffl.com", "--version"]))

    def testOnLinuxNonComFileDoesNotUseShell(self):
        with patch("platform.system", return_value="Linux"):
            with patch.object(MCP, "fflShellMode", False):
                self.assertFalse(MCP.shouldUseShell(["/usr/local/bin/ffl", "--version"]))

    def testExplicitShellModeOverridesEverything(self):
        with patch.object(MCP, "fflShellMode", True):
            self.assertTrue(MCP.shouldUseShell(["ffl", "--version"]))
            self.assertTrue(MCP.shouldUseShell(["ffl.com", "--version"]))

    def testNonComExtensionNotShellOnLinux(self):
        with patch("platform.system", return_value="Linux"):
            with patch.object(MCP, "fflShellMode", False):
                self.assertFalse(MCP.shouldUseShell(["python", "Core.py", "--cli"]))


if __name__ == "__main__":
    unittest.main()
