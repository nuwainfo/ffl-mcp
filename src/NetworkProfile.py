#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
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

"""Network-profile detection used while registering ffl-mcp with an MCP client."""

import ipaddress
import os
import queue
import socket
import threading
import time

from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


syntheticDnsNetwork = ipaddress.ip_network("198.18.0.0/15")
profileEnvKey = "FFL_NETWORK_PROFILE"
syntheticDnsProfile = "synthetic-dns-198-18"
probeHostnames = ("example.com", "stun.cloudflare.com")


def isSyntheticDnsAddress(address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in syntheticDnsNetwork
    except ValueError:
        return False


def getResolvedAddresses(records: Iterable[Tuple[Any, Any, Any, Any, Tuple[Any, ...]]]) -> List[str]:
    return sorted({record[4][0] for record in records})


def detectSyntheticDnsProfile(
    resolvedHosts: Mapping[str, Sequence[str]],
    hostnames: Sequence[str] = probeHostnames,
) -> Optional[str]:
    """Return the relay profile only when every probe has synthetic IPv4 answers."""
    if not hostnames:
        return None

    for hostname in hostnames:
        addresses = resolvedHosts.get(hostname, ())
        if not addresses or not all(isSyntheticDnsAddress(address) for address in addresses):
            return None

    return syntheticDnsProfile


def probeNetworkProfile(
    timeoutSeconds: float = 0.5,
    hostnames: Sequence[str] = probeHostnames,
    resolver: Callable[..., Any] = socket.getaddrinfo,
) -> Optional[str]:
    """Run bounded parallel DNS probes without delaying installation on DNS failures."""
    results: Dict[str, List[str]] = {}
    completed = queue.Queue()
    deadline = time.monotonic() + timeoutSeconds

    def resolve(hostname: str) -> None:
        try:
            records = resolver(hostname, 443, type=socket.SOCK_STREAM)
            addresses = getResolvedAddresses(records)
        except OSError:
            addresses = []

        completed.put((hostname, addresses))

    for hostname in hostnames:
        threading.Thread(target=resolve, args=(hostname,), daemon=True).start()

    while len(results) < len(hostnames):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None

        try:
            hostname, addresses = completed.get(timeout=remaining)
        except queue.Empty:
            return None

        results[hostname] = addresses

    return detectSyntheticDnsProfile(results, hostnames)


def getNetworkProfile(environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    environment = os.environ if environ is None else environ
    value = environment.get(profileEnvKey, "").strip().lower()

    if value == syntheticDnsProfile:
        return {
            "mode": "relay",
            "reason": "syntheticDns19818",
            "automatic": True,
        }

    if value == "relay":
        return {
            "mode": "relay",
            "reason": "configuredRelay",
            "automatic": False,
        }

    if value in {"p2p", "direct"}:
        return {
            "mode": "p2p",
            "reason": "configuredP2p",
            "automatic": False,
        }

    return {
        "mode": "p2p",
        "reason": "p2pFirst",
        "automatic": True,
    }


def resolveShareTransport(
    forceRelay: bool,
    transport: Optional[str],
    networkProfile: Mapping[str, Any],
) -> Dict[str, Any]:
    if transport is not None and transport not in {"p2p", "relay"}:
        raise ValueError("transport must be 'p2p' or 'relay'")

    if transport == "p2p" and forceRelay:
        raise ValueError("transport='p2p' conflicts with forceRelay=True")

    if transport == "relay":
        return {
            "mode": "relay",
            "forceRelay": True,
            "reason": "toolTransport",
            "automatic": False,
            "preferredTunnel": None,
        }

    if transport == "p2p":
        return {
            "mode": "p2p",
            "forceRelay": False,
            "reason": "toolTransport",
            "automatic": False,
            "preferredTunnel": None,
        }

    if forceRelay:
        return {
            "mode": "relay",
            "forceRelay": True,
            "reason": "forceRelay",
            "automatic": False,
            "preferredTunnel": None,
        }

    if networkProfile["mode"] == "relay":
        return {
            "mode": "relay",
            "forceRelay": True,
            "reason": networkProfile["reason"],
            "automatic": networkProfile["automatic"],
            "preferredTunnel": "default:web",
        }

    return {
        "mode": "p2p",
        "forceRelay": False,
        "reason": networkProfile["reason"],
        "automatic": networkProfile["automatic"],
        "preferredTunnel": None,
    }


def hasEnvironmentAssignment(arguments: Sequence[str], key: str) -> bool:
    for index, argument in enumerate(arguments):
        assignment = None
        if argument == "--env" and index + 1 < len(arguments):
            assignment = arguments[index + 1]
        elif argument.startswith("--env="):
            assignment = argument[len("--env="):]

        if assignment and assignment.partition("=")[0] == key:
            return True

    return False


def prepareInstallerArguments(
    arguments: Sequence[str],
    environ: Optional[Mapping[str, str]] = None,
    profileProbe: Callable[[], Optional[str]] = probeNetworkProfile,
) -> List[str]:
    """Add a detected profile unless the caller already chose one."""
    prepared = list(arguments)
    environment = os.environ if environ is None else environ

    if "--uninstall" in prepared:
        return prepared

    if hasEnvironmentAssignment(prepared, profileEnvKey) or environment.get(profileEnvKey):
        return prepared

    profile = profileProbe()
    if profile:
        prepared.extend(["--env", f"{profileEnvKey}={profile}"])

    return prepared
