#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Tests for install-time managed-sandbox network profiling."""

import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.NetworkProfile import (
    detectSyntheticDnsProfile,
    getNetworkProfile,
    prepareInstallerArguments,
    probeNetworkProfile,
    resolveShareTransport,
    syntheticDnsProfile,
)


class SyntheticDnsProfileTest(unittest.TestCase):

    def testDetectsOnlyWhenEveryProbeUsesSyntheticAddresses(self):
        profile = detectSyntheticDnsProfile({
            "example.com": ["198.18.0.1"],
            "stun.cloudflare.com": ["198.19.255.254"],
        })

        self.assertEqual(profile, syntheticDnsProfile)

    def testDoesNotDetectMixedOrMissingAnswers(self):
        self.assertIsNone(detectSyntheticDnsProfile({
            "example.com": ["198.18.0.1"],
            "stun.cloudflare.com": ["1.1.1.1"],
        }))
        self.assertIsNone(detectSyntheticDnsProfile({
            "example.com": ["198.18.0.1"],
        }))

    def testProbeRunsResolversInParallelAndReturnsDetectedProfile(self):
        def resolver(hostname, _port, type):
            self.assertEqual(type, socket.SOCK_STREAM)
            address = "198.18.0.1" if hostname == "example.com" else "198.18.0.2"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

        profile = probeNetworkProfile(timeoutSeconds=0.1, resolver=resolver)

        self.assertEqual(profile, syntheticDnsProfile)


class InstallerProfileTest(unittest.TestCase):

    def testInstallerWritesDetectedProfileAsMcpEnvironment(self):
        arguments = prepareInstallerArguments(
            ["--target", "grok-build"],
            environ={},
            profileProbe=lambda: syntheticDnsProfile,
        )

        self.assertEqual(arguments[-2:], ["--env", f"FFL_NETWORK_PROFILE={syntheticDnsProfile}"])

    def testInstallerPreservesExplicitProfileAndSkipsUninstall(self):
        explicit = prepareInstallerArguments(
            ["--env", "FFL_NETWORK_PROFILE=p2p"],
            environ={},
            profileProbe=lambda: self.fail("profile probe should not run"),
        )

        uninstall = prepareInstallerArguments(
            ["--uninstall"],
            environ={},
            profileProbe=lambda: self.fail("profile probe should not run"),
        )

        self.assertEqual(explicit, ["--env", "FFL_NETWORK_PROFILE=p2p"])
        self.assertEqual(uninstall, ["--uninstall"])


class ShareTransportTest(unittest.TestCase):

    def testSyntheticProfileForcesRelayUnlessToolSelectsP2p(self):
        profile = getNetworkProfile({"FFL_NETWORK_PROFILE": syntheticDnsProfile})
        automatic = resolveShareTransport(False, None, profile)
        override = resolveShareTransport(False, "p2p", profile)

        self.assertEqual(automatic["mode"], "relay")
        self.assertTrue(automatic["forceRelay"])
        self.assertTrue(automatic["automatic"])
        self.assertEqual(automatic["preferredTunnel"], "default:web")
        self.assertEqual(override["mode"], "p2p")
        self.assertFalse(override["forceRelay"])
        self.assertIsNone(override["preferredTunnel"])

    def testConflictingP2pOptionsFailExplicitly(self):
        profile = getNetworkProfile({})

        with self.assertRaises(ValueError):
            resolveShareTransport(True, "p2p", profile)


if __name__ == "__main__":
    unittest.main()
