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
Integration tests for ffl binary execution — no network required.

Verifies that the ffl binary can be found, invoked, and that output is
captured correctly across all execution modes (shell / no-shell, debug logging).
"""

import platform
import shlex
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

import MCP
from IntegrationBase import FflIntegrationBase, requiresFflBinary


@requiresFflBinary
class FflExecutionTest(FflIntegrationBase):

    def testFflVersionSucceeds(self):
        result = self._runFfl(["--version"])
        self.assertEqual(result.returncode, 0)

    def testFflVersionProducesOutput(self):
        result = self._runFfl(["--version"])
        combinedOutput = result.stdout + result.stderr
        self.assertGreater(len(combinedOutput.strip()), 0)

    def testOutputCaptureToTempFile(self):
        logPath = self._makeTempPath(suffix=".log")
        cmd = MCP.buildBaseCommand() + ["--version"]
        useShell = MCP.shouldUseShell(cmd)

        with open(logPath, "w") as logFile:
            if useShell:
                proc = subprocess.Popen(shlex.join(cmd), shell=True, stdout=logFile, stderr=logFile)
            else:
                proc = subprocess.Popen(cmd, shell=False, stdout=logFile, stderr=logFile)
            proc.wait()

        self.assertEqual(proc.returncode, 0)
        with open(logPath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        self.assertGreater(len(content.strip()), 0)

    def testNoShellModeOnWindows(self):
        if platform.system() != "Windows":
            self.skipTest("Windows-only assertion")
        cmd = MCP.buildBaseCommand() + ["--version"]
        self.assertFalse(MCP.shouldUseShell(cmd))

    def testSetupDebugLoggingCreatesFile(self):
        tempPaths = []
        logFile, logPath = MCP.setupDebugLogging(tempPaths=tempPaths)
        self.assertIsNotNone(logPath)
        self.assertIn(logPath, tempPaths)
        self.assertTrue(Path(logPath).exists())
        logFile.close()
        self._trackTempPath(logPath)

    def testSetupDebugLoggingToCustomPath(self):
        customPath = self._makeTempPath(suffix=".log")
        logFile, logPath = MCP.setupDebugLogging(customPath=customPath)
        self.assertEqual(logPath, customPath)
        logFile.close()


if __name__ == "__main__":
    unittest.main()
