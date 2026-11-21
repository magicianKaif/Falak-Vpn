"""Unit test for the `falak status` CLI command (Milestone 2.3)."""

from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import patch

from falak.cli import main
from falak.core import environment as env


class TestCliStatus(unittest.TestCase):
    def test_status_prints_report_and_returns_zero(self) -> None:
        fake_report = env.EnvironmentReport(
            tools=(env.ToolStatus(name="wg", available=True, path="/usr/bin/wg"),),
            network_manager=env.NetworkManagerStatus(installed=False, active=None),
            dns=env.DnsStatus(method=env.DnsMethod.STATIC, detail="static config"),
            routes=env.RouteStatus(
                ipv4_default_routes=(), ipv6_default_routes=(), ipv4_available=True, ipv6_available=True
            ),
        )
        with patch("falak.cli.detect_environment", return_value=fake_report):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["status"])

        self.assertEqual(exit_code, 0)
        self.assertIn("Tools:", stdout.getvalue())
        self.assertIn("DNS:", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
