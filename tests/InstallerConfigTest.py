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

import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "scripts"))

from Build import generateInstallScript, generateUninstallScript
from install.backends import TomlMcpBackend, buildTomlServerConfig, getDefaultGrokConfigPath, removeTomlServerConfig
from install.Install import collectEnv, inferUvxFromSpec, loadAppConfig, normalizeInstallTargets, parseEnvAssignment, parseEnvFile


class InstallerConfigTest(unittest.TestCase):

    def testBuildTomlServerConfig(self):
        entry = {
            "command": "uvx",
            "args": ["--from", "git+https://github.com/nuwainfo/ffl-mcp", "ffl-mcp"],
            "env": {"FFL_USE_STDIN": "1"},
        }
        text = buildTomlServerConfig("ffl", entry)
        self.assertIn("[mcp_servers.ffl]", text)
        self.assertIn('command = "uvx"', text)
        self.assertIn('args = ["--from", "git+https://github.com/nuwainfo/ffl-mcp", "ffl-mcp"]', text)
        self.assertIn("[mcp_servers.ffl.env]", text)
        self.assertIn('FFL_USE_STDIN = "1"', text)

    def testRemoveTomlServerConfigOnlyRemovesTargetServer(self):
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
        updatedText, removed = removeTomlServerConfig(existingText, "ffl")
        self.assertTrue(removed)
        self.assertNotIn("[mcp_servers.ffl]", updatedText)
        self.assertNotIn("[mcp_servers.ffl.env]", updatedText)
        self.assertIn("[mcp_servers.other]", updatedText)
        self.assertIn("[mcp_servers.after]", updatedText)

    def testTomlBackendRejectsExistingWithoutOverwrite(self):
        with tempfile.TemporaryDirectory() as tempDir:
            configPath = pathlib.Path(tempDir) / "config.toml"
            installer = TomlMcpBackend("codex", "Codex", configPath)
            entry = {"command": "uvx", "args": ["ffl-mcp"], "env": {}}
            installer.install("ffl", entry, overwrite=False)
            with self.assertRaises(RuntimeError):
                installer.install("ffl", entry, overwrite=False)

    def testGrokInstallerWritesCompatibleMcpServerToml(self):
        with tempfile.TemporaryDirectory() as tempDir:
            configPath = pathlib.Path(tempDir) / "config.toml"
            installer = TomlMcpBackend("grok-build", "Grok Build", configPath)
            entry = {
                "command": "ffl-mcp.exe",
                "args": [],
                "env": {"FFL_USE_STDIN": "1"},
            }
            existingText = '[mcp_servers.other]\ncommand = "npx"\n'

            configPath.write_text(existingText, encoding="utf-8")
            result = installer.install("ffl", entry, overwrite=False)
            updatedText = configPath.read_text(encoding="utf-8")

            self.assertEqual(result.target, "grok-build")
            self.assertIn('[mcp_servers.other]', updatedText)
            self.assertIn('[mcp_servers.ffl]', updatedText)
            self.assertIn('command = "ffl-mcp.exe"', updatedText)
            self.assertIn('[mcp_servers.ffl.env]', updatedText)
            self.assertIn('FFL_USE_STDIN = "1"', updatedText)

    def testDefaultGrokConfigPathHonorsGrokHome(self):
        previousValue = os.environ.get("GROK_HOME")
        try:
            os.environ["GROK_HOME"] = "C:/test/grok-home"
            self.assertEqual(getDefaultGrokConfigPath(), pathlib.Path("C:/test/grok-home/config.toml"))
        finally:
            if previousValue is None:
                os.environ.pop("GROK_HOME", None)
            else:
                os.environ["GROK_HOME"] = previousValue

    def testLegacyTargetsResolveToCanonicalBackends(self):
        targets = normalizeInstallTargets([
            "claude-cli",
            "codex-cli",
            "codex-desktop",
            "grok",
        ])
        self.assertEqual(targets, ["claude-code", "codex", "grok-build"])

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


class AppConfigTest(unittest.TestCase):
    """`install/Install.py` is generic; these confirm the external-manifest mechanism it reads app-specific
    defaults from actually works, independent of any particular app's own install.config.json content."""

    def testLoadAppConfigReadsManifest(self):
        with tempfile.TemporaryDirectory() as tempDir:
            configPath = pathlib.Path(tempDir) / "install.config.json"
            configPath.write_text(
                '{"serverName": "demo", "entrypoint": "demo-mcp", "distributionName": "demo-mcp", '
                '"envKeys": ["DEMO_TOKEN"], "binaryEnvVar": "DEMO_BINARY", '
                '"defaultEnvValues": {"DEMO_TOKEN": "fallback"}, "envWarnings": {"DEMO_TOKEN": "set a token"}}',
                encoding="utf-8",
            )
            appConfig = loadAppConfig(str(configPath))

        self.assertEqual(appConfig.serverName, "demo")
        self.assertEqual(appConfig.entrypoint, "demo-mcp")
        self.assertEqual(appConfig.distributionName, "demo-mcp")
        self.assertEqual(appConfig.envKeys, ["DEMO_TOKEN"])
        self.assertEqual(appConfig.binaryEnvVar, "DEMO_BINARY")
        self.assertEqual(appConfig.defaultEnvValues, {"DEMO_TOKEN": "fallback"})
        self.assertEqual(appConfig.envWarnings, {"DEMO_TOKEN": "set a token"})

    def testLoadAppConfigMissingFileRaises(self):
        with self.assertRaises(FileNotFoundError):
            loadAppConfig("/nonexistent/install.config.json")

    def testLoadAppConfigRequiresServerNameAndEntrypoint(self):
        with tempfile.TemporaryDirectory() as tempDir:
            configPath = pathlib.Path(tempDir) / "install.config.json"
            configPath.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                loadAppConfig(str(configPath))

    def testFflMcpOwnManifestLoadsAndMatchesDocumentedDefaults(self):
        repoRoot = pathlib.Path(__file__).resolve().parents[1]
        appConfig = loadAppConfig(str(repoRoot / "install.config.json"))

        self.assertEqual(appConfig.serverName, "ffl")
        self.assertEqual(appConfig.entrypoint, "ffl-mcp")
        self.assertEqual(appConfig.distributionName, "ffl-mcp")
        self.assertEqual(set(appConfig.envKeys), {"FFL_USE_STDIN", "ALLOWED_BASE_DIR"})
        self.assertEqual(appConfig.binaryEnvVar, "FFL_MCP_BINARY")

    def testParseEnvAssignmentSplitsOnFirstEquals(self):
        self.assertEqual(parseEnvAssignment("KEY=a=b"), ("KEY", "a=b"))
        with self.assertRaises(ValueError):
            parseEnvAssignment("NO_EQUALS_SIGN")

    def testParseEnvFileSkipsBlankLinesAndComments(self):
        with tempfile.TemporaryDirectory() as tempDir:
            envPath = pathlib.Path(tempDir) / ".env"
            envPath.write_text("# comment\n\nALLOWED_BASE_DIR=/tmp/shared\nFFL_USE_STDIN=1\n", encoding="utf-8")
            self.assertEqual(
                parseEnvFile(envPath),
                {"ALLOWED_BASE_DIR": "/tmp/shared", "FFL_USE_STDIN": "1"},
            )

    def testCollectEnvOnlyForwardsConfiguredKeys(self):
        env = collectEnv({"ALLOWED_BASE_DIR": "/tmp", "UNRELATED": "ignored"}, ["ALLOWED_BASE_DIR", "FFL_USE_STDIN"])
        self.assertEqual(env, {"ALLOWED_BASE_DIR": "/tmp"})

    def testInferUvxFromSpecReturnsNoneWithoutDistributionName(self):
        self.assertIsNone(inferUvxFromSpec(None))


if __name__ == "__main__":
    unittest.main()
