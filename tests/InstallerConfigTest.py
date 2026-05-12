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
"""Tests for installer config generation."""

import pathlib
import tempfile
import unittest

from install.install import (
    CodexConfigInstaller,
    buildCodexServerToml,
    removeCodexServerToml,
)


class CodexConfigTest(unittest.TestCase):

    def testBuildCodexServerToml(self):
        entry = {
            "command": "uvx",
            "args": ["--from", "git+https://github.com/nuwainfo/ffl-mcp", "ffl-mcp"],
            "env": {"FFL_USE_STDIN": "1"},
        }
        text = buildCodexServerToml("ffl", entry)
        self.assertIn("[mcp_servers.ffl]", text)
        self.assertIn('command = "uvx"', text)
        self.assertIn('args = ["--from", "git+https://github.com/nuwainfo/ffl-mcp", "ffl-mcp"]', text)
        self.assertIn("[mcp_servers.ffl.env]", text)
        self.assertIn('FFL_USE_STDIN = "1"', text)

    def testRemoveCodexServerTomlOnlyRemovesTargetServer(self):
        existingText = """
[mcp_servers.other]
command = "npx"

[mcp_servers.ffl]
command = "uvx"

[mcp_servers.ffl.env]
FFL_USE_STDIN = "1"

[mcp_servers.after]
command = "node"
""".lstrip()
        updatedText, removed = removeCodexServerToml(existingText, "ffl")
        self.assertTrue(removed)
        self.assertNotIn("[mcp_servers.ffl]", updatedText)
        self.assertNotIn("[mcp_servers.ffl.env]", updatedText)
        self.assertIn("[mcp_servers.other]", updatedText)
        self.assertIn("[mcp_servers.after]", updatedText)

    def testCodexInstallerRejectsExistingWithoutOverwrite(self):
        with tempfile.TemporaryDirectory() as tempDir:
            installer = CodexConfigInstaller(pathlib.Path(tempDir) / "config.toml")
            entry = {"command": "uvx", "args": ["ffl-mcp"], "env": {}}
            configText = buildCodexServerToml("ffl", entry)
            with self.assertRaises(RuntimeError):
                installer.addServer(configText, "ffl", entry, overwrite=False)


if __name__ == "__main__":
    unittest.main()
