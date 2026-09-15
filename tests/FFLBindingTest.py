#!/usr/bin/env python
"""Tests for the ffl-python integration boundary."""

import sys
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import MCP


class FakeShareSession:
    link = "https://ffl.example.test/share"
    pid = 1234
    argv = ("ffl", "share", "file.txt")
    running = True
    stdout = ""
    event_history = ()

    def stop(self):
        self.running = False

    def close(self):
        self.running = False


class FFLBindingTest(unittest.TestCase):
    def tearDown(self):
        for session in MCP.sessionStore.listSessions():
            MCP.sessionStore.stopSession(session["sessionId"])

    def testShareDelegatesToBindingAndCapturesExternalHookEvents(self):
        session = FakeShareSession()
        with patch.object(MCP.ffl, "share", return_value=session) as share:
            result = MCP.shareWithFfl(
                "file.txt", None, [], None, False, None, None, 1, 30,
                10, "http://127.0.0.1:9000/events", None, False,
            )

        self.assertEqual(result["link"], session.link)
        self.assertEqual(result["pid"], session.pid)
        self.assertEqual(share.call_args.kwargs["hook_url"], "http://127.0.0.1:9000/events")
        self.assertTrue(share.call_args.kwargs["capture_hook_events"])

    def testSessionEventsUseBindingHistoryWithoutPreviewSidecar(self):
        session = FakeShareSession()
        session.event_history = (
            SimpleNamespace(
                name="/hook/transfer/progress",
                timestamp="2026-09-15T12:00:00Z",
                data={"bytes": 1024},
            ),
        )
        sessionId = "binding-history"
        MCP.sessionStore.addSession({
            "sessionId": sessionId,
            "session": session,
            "link": session.link,
            "startedAt": 0,
            "tempPaths": [],
            "hookServer": None,
        })

        result = MCP.fflGetSessionEvents(sessionId)

        self.assertTrue(result["ok"])
        self.assertEqual(result["events"], [{
            "event": "/hook/transfer/progress",
            "timestamp": "2026-09-15T12:00:00Z",
            "data": {"bytes": 1024},
        }])

    def testShareTextStreamsWithoutCreatingTemporaryFile(self):
        session = FakeShareSession()
        with patch.object(MCP, "fflUseStdin", True), \
             patch.object(MCP.ffl, "share_stream", return_value=session) as shareStream, \
             patch.object(MCP, "createTempFile") as createTempFile:
            result = MCP.fflShareText("stream me", name="message.txt")

        self.assertEqual(result["link"], session.link)
        self.assertFalse(createTempFile.called)
        source, contentName = shareStream.call_args.args[:2]
        self.assertEqual(contentName, "message.txt")
        self.assertEqual(source.read(), b"stream me")

    def testShareBase64UsesBindingTemporaryOwnershipWhenNotStreaming(self):
        session = FakeShareSession()
        with patch.object(MCP, "fflUseStdin", False), \
             patch.object(MCP.ffl, "share_bytes", return_value=session) as shareBytes, \
             patch.object(MCP, "createTempFile") as createTempFile:
            result = MCP.fflShareBase64("AP+AQQ==", name="payload.bin")

        self.assertEqual(result["link"], session.link)
        self.assertFalse(createTempFile.called)
        self.assertEqual(shareBytes.call_args.args[:2], (b"\x00\xff\x80A", "payload.bin"))

    def testDownloadReturnsBindingMetadataInsteadOfParsingCliOutput(self):
        downloadResult = SimpleNamespace(
            return_code=0,
            output_path=Path("received.bin"),
            transfer_mode=SimpleNamespace(name="WEBRTC_P2P"),
        )
        with patch.object(MCP.ffl, "download", return_value=downloadResult) as download:
            result = MCP.fflDownload(
                "https://ffl.example.test/share",
                outputPath="received.bin",
                resume=True,
                pickupCode="123456",
            )

        self.assertEqual(result, {
            "ok": True,
            "returncode": 0,
            "url": "https://ffl.example.test/share",
            "transferMode": "webrtc_p2p",
            "outputPath": "received.bin",
        })
        self.assertTrue(download.call_args.kwargs["resume"])
        self.assertEqual(download.call_args.kwargs["pickup_code"], "123456")

    def testKeygenReturnsPathsReportedByBinding(self):
        keygenResult = SimpleNamespace(
            return_code=0,
            private_key_path=Path("alice.fflkey"),
            public_key_path=Path("alice.fflpub"),
            stdout="Generated key pair\n",
        )
        with patch.object(MCP.ffl, "keygen", return_value=keygenResult) as keygen:
            result = MCP.fflKeygen("alice")

        self.assertEqual(result, {
            "ok": True,
            "returncode": 0,
            "privateKeyPath": "alice.fflkey",
            "publicKeyPath": "alice.fflpub",
            "output": "Generated key pair",
        })
        self.assertEqual(keygen.call_args.args, ("alice",))


if __name__ == "__main__":
    unittest.main()
