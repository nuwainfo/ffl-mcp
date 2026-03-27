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
Shared base class and skip markers for integration tests that need the ffl binary.

Import this in each integration test file:
    from IntegrationBase import FflIntegrationBase, requiresFflBinary, requiresNetwork
"""

import logging
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP

logger = logging.getLogger("fflMcpIntegrationBase")


def callTool(tool, **kwargs):
    """Call an MCP FunctionTool's underlying function directly."""
    fn = tool.fn if hasattr(tool, "fn") else tool
    return fn(**kwargs)


def _fflBinaryAvailable() -> bool:
    """Return True if the ffl binary exists and executes successfully."""
    fflBin = MCP.resolveDefaultFflBin()
    if fflBin != "ffl" and not Path(fflBin).exists():
        return False
    try:
        cmd = [fflBin, "--version"]
        useShell = MCP.shouldUseShell(cmd)
        if useShell:
            result = subprocess.run(shlex.join(cmd), shell=True, capture_output=True, timeout=10)
        else:
            result = subprocess.run(cmd, shell=False, capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception as exc:
        logger.debug("ffl binary check failed: %s", exc)
        return False


requiresFflBinary = unittest.skipUnless(_fflBinaryAvailable(), "ffl binary not available or not executable")
requiresNetwork = unittest.skipUnless(
    os.environ.get("FFL_INTEGRATION_TESTS") == "1",
    "Set FFL_INTEGRATION_TESTS=1 to run network-dependent tests",
)


class FflIntegrationBase(unittest.TestCase):
    """
    Base class for integration tests.

    Provides:
    - tearDown: stop all active sessions and remove tracked temp files
    - _trackTempPath(): register a path for cleanup after the test
    - _makeTempPath(): create and track a temp file, returns its path
    - _runFfl(): run ffl with the correct shell mode, returns CompletedProcess
    """

    def setUp(self):
        self._trackedPaths = []

    def tearDown(self):
        for session in MCP.sessionStore.listSessions():
            try:
                MCP.sessionStore.stopSession(session["sessionId"])
            except Exception as exc:
                logger.debug("Failed to stop session %s in tearDown: %s", session.get("sessionId"), exc)

        for path in self._trackedPaths:
            try:
                os.remove(path)
            except Exception as exc:
                logger.debug("Failed to remove tracked path %s: %s", path, exc)

    def _trackTempPath(self, path: str) -> str:
        self._trackedPaths.append(path)
        return path

    def _makeTempPath(self, suffix: str = ".txt") -> str:
        tempFile = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tempFile.close()
        return self._trackTempPath(tempFile.name)

    def _runFfl(self, args, timeout: int = 10) -> subprocess.CompletedProcess:
        cmd = MCP.buildBaseCommand() + args
        useShell = MCP.shouldUseShell(cmd)
        if useShell:
            return subprocess.run(shlex.join(cmd), shell=True, capture_output=True, text=True, timeout=timeout)
        return subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)
