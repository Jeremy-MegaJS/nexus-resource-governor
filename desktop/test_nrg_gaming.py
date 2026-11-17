import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nrg_gaming


class GamingSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.state_dir = root / "nrg"
        self.state_file = self.state_dir / "gaming-session.json"
        self.patches = [
            patch.object(nrg_gaming, "STATE_DIR", self.state_dir),
            patch.object(nrg_gaming, "STATE_FILE", self.state_file),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def write_state(self, units=None):
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps({
            "schema": 1,
            "created_unix": 1,
            "expires_unix": 9999999999,
            "mode": "cloud",
            "target": "test-game.scope",
            "units": units or [{"unit": "test-game.scope", "cpu_weight": 100, "io_weight": 100}],
            "baloo": {"was_active": False},
            "power_profile": None,
            "power_profile_changed": False,
        }))

    def test_invalid_duration_is_rejected_before_discovery(self):
        with patch.object(nrg_gaming, "find_target") as find_target:
            with self.assertRaises(ValueError):
                nrg_gaming.start_session("cloud", 14)
            find_target.assert_not_called()
        self.assertFalse(self.state_file.exists())

    def test_restore_reapplies_values_even_if_unit_is_stopped(self):
        self.write_state()
        with (
            patch.object(nrg_gaming, "set_weights") as set_weights,
            patch.object(nrg_gaming, "cancel_rollback"),
            patch.object(nrg_gaming, "active", return_value=False),
        ):
            result = nrg_gaming.restore_session()
        self.assertTrue(result["ok"])
        set_weights.assert_called_once_with("test-game.scope", 100, 100)
        self.assertFalse(self.state_file.exists())

    def test_failed_restore_retains_transaction_for_retry(self):
        self.write_state()
        with (
            patch.object(nrg_gaming, "set_weights", side_effect=RuntimeError("test failure")),
            patch.object(nrg_gaming, "cancel_rollback"),
        ):
            result = nrg_gaming.restore_session()
        self.assertFalse(result["ok"])
        self.assertTrue(result["active"])
        self.assertTrue(self.state_file.exists())

    def test_status_reports_remaining_session(self):
        self.write_state()
        with patch.object(nrg_gaming.time, "time", return_value=100):
            status = nrg_gaming.session_status()
        self.assertTrue(status["active"])
        self.assertEqual(status["remaining_seconds"], 9999999899)


if __name__ == "__main__":
    unittest.main()
