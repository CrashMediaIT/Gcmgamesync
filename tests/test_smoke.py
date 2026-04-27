from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gcmgamesync_client.__main__ import validate_server_url
from gcmgamesync_client.scanner import MANIFEST, detect_emulators, should_sync
from gcmgamesync_server.auth import _totp, new_totp_secret, verify_totp
from gcmgamesync_server.storage import write_versioned_file


class GcmSmokeTests(unittest.TestCase):
    def test_manifest_contains_requested_emulators_and_dolphin_dev(self):
        ids = {item["id"] for item in MANIFEST["emulators"]}
        self.assertIn("dolphin-dev", ids)
        self.assertTrue({"duckstation", "pcsx2-nightly", "rpcs3-nightly", "xenia-canary", "xemu", "cemu", "retroarch", "eden-nightly"}.issubset(ids))

    def test_config_exclusion_prevents_device_local_config_sync(self):
        dolphin = next(item for item in MANIFEST["emulators"] if item["id"] == "dolphin-dev")
        self.assertTrue(should_sync("User/GC/MemoryCardA.USA.raw", dolphin))
        self.assertFalse(should_sync("User/Config/Dolphin.ini", dolphin))

    def test_detect_emulator_and_portable_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            duck = root / "DuckStation"
            duck.mkdir()
            (duck / "portable.txt").write_text("", encoding="utf-8")
            found = detect_emulators(root)
            self.assertEqual(found[0]["id"], "duckstation")
            self.assertTrue(found[0]["portable"])

    def test_versioned_storage_keeps_only_changed_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertTrue(write_versioned_file(root, "u@example.com", "saves/a.sav", b"1")["changed"])
            self.assertFalse(write_versioned_file(root, "u@example.com", "saves/a.sav", b"1")["changed"])
            for index in range(2, 9):
                write_versioned_file(root, "u@example.com", "saves/a.sav", str(index).encode())
            versions = list((root / "versions" / "u@example.com" / "saves" / "a.sav").iterdir())
            self.assertLessEqual(len(versions), 4)

    def test_client_requires_https_except_localhost(self):
        self.assertEqual(validate_server_url("https://sync.example.com"), "https://sync.example.com")
        self.assertEqual(validate_server_url("http://localhost:8080"), "http://localhost:8080")
        with self.assertRaises(ValueError):
            validate_server_url("http://sync.example.com")

    def test_totp_verification(self):
        secret = new_totp_secret()
        code = _totp(secret, 123456)
        self.assertTrue(verify_totp(secret, code, now=123456 * 30, window=0))


if __name__ == "__main__":
    unittest.main()
