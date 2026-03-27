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
"""Tests for isPathAllowed() — ALLOWED_BASE_DIR path restriction."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class PathSecurityTest(unittest.TestCase):

    def testAllPathsAllowedWhenNoBaseDir(self):
        with patch.object(MCP, "allowedBaseDir", None):
            self.assertTrue(MCP.isPathAllowed(Path(tempfile.gettempdir())))
            self.assertTrue(MCP.isPathAllowed(Path("C:/")))

    def testBaseDirItselfIsAllowed(self):
        with tempfile.TemporaryDirectory() as baseDir:
            with patch.object(MCP, "allowedBaseDir", baseDir):
                self.assertTrue(MCP.isPathAllowed(Path(baseDir)))

    def testSubpathWithinBaseDirIsAllowed(self):
        with tempfile.TemporaryDirectory() as baseDir:
            with patch.object(MCP, "allowedBaseDir", baseDir):
                subPath = Path(baseDir) / "subdir" / "file.txt"
                self.assertTrue(MCP.isPathAllowed(subPath))

    def testPathOutsideBaseDirIsRejected(self):
        with tempfile.TemporaryDirectory() as baseDir:
            with tempfile.TemporaryDirectory() as otherDir:
                with patch.object(MCP, "allowedBaseDir", baseDir):
                    self.assertFalse(MCP.isPathAllowed(Path(otherDir) / "file.txt"))


if __name__ == "__main__":
    unittest.main()
