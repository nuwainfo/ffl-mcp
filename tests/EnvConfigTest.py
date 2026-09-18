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
  - ParseFFLDebugTest  — FFL_DEBUG path and flag parsing
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class ParseFFLDebugTest(unittest.TestCase):

    def testDisabledWhenEmpty(self):
        with patch.dict(os.environ, {"FFL_DEBUG": ""}):
            enabled, path = MCP.parseFFLDebug()
        self.assertFalse(enabled)
        self.assertIsNone(path)

    def testDisabledWhenNotSet(self):
        env = {k: v for k, v in os.environ.items() if k != "FFL_DEBUG"}
        with patch.dict(os.environ, env, clear=True):
            enabled, path = MCP.parseFFLDebug()
        self.assertFalse(enabled)
        self.assertIsNone(path)

    def testEnabledWithOne(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "1"}):
            enabled, path = MCP.parseFFLDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testEnabledWithTrue(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "true"}):
            enabled, path = MCP.parseFFLDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testEnabledWithYes(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "yes"}):
            enabled, path = MCP.parseFFLDebug()
        self.assertTrue(enabled)
        self.assertIsNone(path)

    def testCustomWindowsPath(self):
        with patch.dict(os.environ, {"FFL_DEBUG": r"D:\mcp.log"}):
            enabled, path = MCP.parseFFLDebug()
        self.assertTrue(enabled)
        self.assertEqual(path, r"D:\mcp.log")

    def testCustomUnixPath(self):
        with patch.dict(os.environ, {"FFL_DEBUG": "/tmp/ffl_debug.log"}):
            enabled, path = MCP.parseFFLDebug()
        self.assertTrue(enabled)
        self.assertEqual(path, "/tmp/ffl_debug.log")


if __name__ == "__main__":
    unittest.main()
