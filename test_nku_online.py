import json
import subprocess
import unittest
from unittest import mock

import nku_online


class TailscaleTargetTests(unittest.TestCase):
    @mock.patch.object(nku_online, "run_command")
    def test_peer_null_during_tailscale_restart_is_offline(self, run_command):
        run_command.return_value = subprocess.CompletedProcess(
            ["tailscale", "status", "--json"], 0, json.dumps({"Peer": None}), ""
        )

        with mock.patch.dict(nku_online.os.environ, {"TAILSCALE_TARGETS": ""}):
            self.assertEqual(nku_online.tailscale_targets(), [])

    def test_generated_mac_is_locally_administered_unicast(self):
        mac = nku_online.random_mac()
        octets = bytes.fromhex(mac.replace(":", ""))

        self.assertEqual(len(octets), 6)
        self.assertEqual(octets[0] & 0x03, 0x02)


class RecoveryPolicyTests(unittest.TestCase):
    @mock.patch.object(nku_online.time, "sleep")
    @mock.patch.object(nku_online, "run_command")
    @mock.patch.object(nku_online, "probe_once", return_value=False)
    @mock.patch.object(nku_online, "verify_profile", return_value=False)
    @mock.patch.object(nku_online, "active_profile", return_value="Xiaomi_NKU")
    @mock.patch.object(nku_online, "connect_profile", return_value=True)
    def test_private_wifi_mac_is_never_rotated(
        self,
        connect_profile,
        _active_profile,
        _verify_profile,
        _probe_once,
        _run_command,
        _sleep,
    ):
        self.assertFalse(nku_online.recover(force_all=True))

        self.assertNotIn(
            mock.call("Xiaomi_NKU", rotate_mac=True), connect_profile.call_args_list
        )
        self.assertIn(
            mock.call("NKU_WLAN", rotate_mac=True), connect_profile.call_args_list
        )


if __name__ == "__main__":
    unittest.main()
