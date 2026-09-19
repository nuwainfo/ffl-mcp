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
"""Tests for ffl-mcp's own installer wiring.

The generic installer mechanism itself (backends, AppConfig loading, env
parsing) now lives in the separate `mcp-install` package (installed via
`[tool.uv.sources]` as an editable sibling checkout — see pyproject.toml) and
is tested there. These tests only cover the ffl-mcp-specific glue: that
ffl-mcp's own `install.config.json` is valid and matches its documented
defaults, and that the standalone-binary installer script stays in sync.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from Build import generateInstallScript, generateUninstallScript
from mcp_install.Install import loadAppConfig


class InstallerConfigTest(unittest.TestCase):

    def testFflMcpOwnManifestLoadsAndMatchesDocumentedDefaults(self):
        repoRoot = pathlib.Path(__file__).resolve().parents[1]
        appConfig = loadAppConfig(str(repoRoot / "install.config.json"))

        self.assertEqual(appConfig.serverName, "ffl")
        self.assertEqual(appConfig.entrypoint, "ffl-mcp")
        self.assertEqual(appConfig.distributionName, "ffl-mcp")
        self.assertEqual(set(appConfig.envKeys), {"FFL_USE_STDIN", "ALLOWED_BASE_DIR"})
        self.assertEqual(appConfig.binaryEnvVar, "FFL_MCP_BINARY")

    def testStandaloneInstallerDelegatesToTheSameBackend(self):
        installScript = generateInstallScript()
        uninstallScript = generateUninstallScript()

        self.assertIn("& $binaryPath install --target all --overwrite", installScript)
        self.assertIn("& $binaryPath uninstall --target all", uninstallScript)
        self.assertIn("$installedVersion = & $binaryPath --version", installScript)
        self.assertNotIn("Codex config", installScript)
        self.assertNotIn("Grok Build config", installScript)

    def testLocalBindingBuildUsesTheSupportedFastMcpVersion(self):
        repoRoot = pathlib.Path(__file__).resolve().parents[1]
        buildText = (repoRoot / "scripts" / "Build.py").read_text(encoding="utf-8")
        self.assertIn("FAST_MCP_REQUIREMENT", buildText)
        self.assertNotIn('"fastmcp>=2,<3"', buildText)


if __name__ == "__main__":
    unittest.main()
