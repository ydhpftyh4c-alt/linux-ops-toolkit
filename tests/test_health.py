from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import socket
import subprocess
import unittest

from opskit import health
from opskit.__main__ import main


class HealthTests(unittest.TestCase):
    def test_threshold_boundaries(self):
        self.assertEqual(health.usage_status(84.9, 85, 95), "OK")
        self.assertEqual(health.usage_status(85, 85, 95), "WARNING")
        self.assertEqual(health.usage_status(95, 85, 95), "CRITICAL")
        with self.assertRaises(ValueError):
            health.usage_status(10, 95, 85)

    def test_memory_uses_available_instead_of_free(self):
        self.assertEqual(health.parse_meminfo("MemTotal: 1000 kB\nMemFree: 10 kB\nMemAvailable: 400 kB\n"), 60)
        with self.assertRaises(ValueError):
            health.parse_meminfo("MemTotal: 10 kB\nMemAvailable: 20 kB\n")

    def test_missing_proc_is_explicit_unknown(self):
        self.assertEqual(health.memory_check(Path("does-not-exist/meminfo")).status, "UNKNOWN")

    def test_systemd_no_shell_and_inactive_detection(self):
        with patch("opskit.health.subprocess.run", return_value=subprocess.CompletedProcess([], 3, "inactive\n", "")) as run:
            self.assertEqual(health.service_check("nginx.service").status, "CRITICAL")
            self.assertEqual(run.call_args.args[0], ["systemctl", "is-active", "--", "nginx.service"])
        with self.assertRaises(ValueError):
            health.service_check("nginx; rm -rf /")

    def test_service_timeout_is_unknown(self):
        with patch("opskit.health.subprocess.run", side_effect=subprocess.TimeoutExpired("systemctl", 3)):
            self.assertEqual(health.service_check("nginx").status, "UNKNOWN")

    def test_tcp_listener(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            self.assertEqual(health.tcp_check("127.0.0.1", listener.getsockname()[1]).status, "OK")

    def test_report_output_and_exit_code(self):
        data = health.report([health.Check("disk", "WARNING", "example")])
        self.assertEqual(data["exit_code"], 1)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            health.write_report(path, data)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), data)
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_cli_rejects_invalid_port_and_thresholds(self):
        self.assertEqual(main(["health", "--skip-memory", "--tcp", "localhost", "99999"]), 3)
        self.assertEqual(main(["health", "--skip-memory", "--warning", "99", "--critical", "90"]), 3)
