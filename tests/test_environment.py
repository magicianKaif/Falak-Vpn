"""Unit tests for falak.core.environment.

All external command execution and filesystem inspection is mocked -
these tests never depend on, or alter, the actual host system's
WireGuard tools, NetworkManager, DNS configuration, or routing table.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from falak.core import environment as env
from falak.utils.shell import CommandResult, ShellError

# ---------------------------------------------------------------------------
# Pure parsing logic
# ---------------------------------------------------------------------------


class TestParseDefaultRouteLines(unittest.TestCase):
    def test_parses_gateway_and_interface(self) -> None:
        output = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
        entries = env._parse_default_route_lines(output)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].gateway, "192.168.1.1")
        self.assertEqual(entries[0].interface, "eth0")

    def test_ignores_non_default_lines(self) -> None:
        output = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n"
        entries = env._parse_default_route_lines(output)
        self.assertEqual(entries, ())

    def test_empty_output_yields_no_entries(self) -> None:
        self.assertEqual(env._parse_default_route_lines(""), ())

    def test_multiple_default_routes_all_parsed(self) -> None:
        output = (
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "default via 192.168.2.1 dev wlan0 metric 600\n"
        )
        entries = env._parse_default_route_lines(output)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1].interface, "wlan0")

    def test_line_missing_dev_leaves_interface_none(self) -> None:
        output = "default via 192.168.1.1\n"
        entries = env._parse_default_route_lines(output)
        self.assertEqual(entries[0].gateway, "192.168.1.1")
        self.assertIsNone(entries[0].interface)


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------


class TestDetectTool(unittest.TestCase):
    @patch("falak.core.environment.shutil.which", return_value=None)
    def test_missing_tool_is_unavailable(self, _mock_which) -> None:
        status = env._detect_tool("wg", version_args=("--version",))
        self.assertFalse(status.available)
        self.assertIsNone(status.path)

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/bin/wg")
    def test_present_tool_reports_version(self, _mock_which, mock_run) -> None:
        mock_run.return_value = CommandResult(
            args=("wg", "--version"),
            returncode=0,
            stdout="wireguard-tools v1.0.20210914\n",
            stderr="",
        )
        status = env._detect_tool("wg", version_args=("--version",))
        self.assertTrue(status.available)
        self.assertEqual(status.path, "/usr/bin/wg")
        self.assertEqual(status.version, "wireguard-tools v1.0.20210914")

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/bin/wg-quick")
    def test_version_probe_failure_is_non_fatal(self, _mock_which, mock_run) -> None:
        mock_run.side_effect = ShellError("boom")
        status = env._detect_tool("wg-quick", version_args=("--version",))
        self.assertTrue(status.available)
        self.assertIsNone(status.version)

    @patch("falak.core.environment.shutil.which", return_value="/usr/bin/wg-quick")
    def test_none_version_args_skips_probe(self, _mock_which) -> None:
        status = env._detect_tool("wg-quick", version_args=None)
        self.assertTrue(status.available)
        self.assertIsNone(status.version)


# ---------------------------------------------------------------------------
# NetworkManager detection
# ---------------------------------------------------------------------------


class TestDetectNetworkManager(unittest.TestCase):
    @patch("falak.core.environment.shutil.which", return_value=None)
    def test_nmcli_missing_means_not_installed(self, _mock_which) -> None:
        status = env._detect_network_manager()
        self.assertFalse(status.installed)
        self.assertIsNone(status.active)

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/bin/nmcli")
    def test_installed_active_with_interfaces(self, _mock_which, mock_run) -> None:
        def side_effect(args, timeout=10.0, **kwargs):
            if args[:2] == ["systemctl", "is-active"]:
                return CommandResult(args=tuple(args), returncode=0, stdout="active\n", stderr="")
            if args[0] == "nmcli":
                return CommandResult(
                    args=tuple(args),
                    returncode=0,
                    stdout="eth0:connected:Wired connection 1\nwlan0:disconnected:--\n",
                    stderr="",
                )
            raise AssertionError(f"unexpected command: {args}")

        mock_run.side_effect = side_effect
        status = env._detect_network_manager()
        self.assertTrue(status.installed)
        self.assertTrue(status.active)
        self.assertEqual(status.active_interfaces, ("eth0",))

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/bin/nmcli")
    def test_nmcli_query_failure_is_non_fatal(self, _mock_which, mock_run) -> None:
        def side_effect(args, timeout=10.0, **kwargs):
            if args[:2] == ["systemctl", "is-active"]:
                return CommandResult(args=tuple(args), returncode=3, stdout="inactive\n", stderr="")
            if args[0] == "nmcli":
                raise ShellError("nmcli timed out")
            raise AssertionError(f"unexpected command: {args}")

        mock_run.side_effect = side_effect
        status = env._detect_network_manager()
        self.assertTrue(status.installed)
        self.assertFalse(status.active)
        self.assertEqual(status.active_interfaces, ())


# ---------------------------------------------------------------------------
# DNS detection (adaptive, fail-safe)
# ---------------------------------------------------------------------------


class TestDetectDns(unittest.TestCase):
    @patch("falak.core.environment.os.path.realpath")
    @patch("falak.core.environment.os.path.islink", return_value=True)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_systemd_resolved_via_symlink(self, _exists, _islink, mock_realpath) -> None:
        mock_realpath.return_value = "/run/systemd/resolve/stub-resolv.conf"
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.SYSTEMD_RESOLVED)
        self.assertTrue(status.safe_for_automatic_management)

    @patch("falak.core.environment._service_active", return_value=True)
    @patch("falak.core.environment.os.path.realpath", return_value="/etc/resolv.conf")
    @patch("falak.core.environment.os.path.islink", return_value=False)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_systemd_resolved_via_active_service_fallback(
        self, _exists, _islink, _realpath, _service_active
    ) -> None:
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.SYSTEMD_RESOLVED)

    @patch("falak.core.environment.os.path.realpath")
    @patch("falak.core.environment.os.path.islink", return_value=True)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_resolvconf_via_symlink(self, _exists, _islink, mock_realpath) -> None:
        mock_realpath.return_value = "/run/resolvconf/resolv.conf"
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.RESOLVCONF)

    @patch("falak.core.environment.os.path.realpath")
    @patch("falak.core.environment.os.path.islink", return_value=True)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_networkmanager_via_symlink(self, _exists, _islink, mock_realpath) -> None:
        mock_realpath.return_value = "/var/run/NetworkManager/resolv.conf"
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.NETWORK_MANAGER)

    @patch("falak.core.environment._service_active", return_value=False)
    @patch("falak.core.environment.shutil.which", return_value=None)
    @patch("falak.core.environment.os.path.realpath", return_value="/etc/resolv.conf")
    @patch("falak.core.environment.os.path.islink", return_value=False)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_static_file(self, _exists, _islink, _realpath, _which, _service_active) -> None:
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.STATIC)
        self.assertTrue(status.safe_for_automatic_management)

    @patch("falak.core.environment._service_active", return_value=False)
    @patch("falak.core.environment.os.path.exists", return_value=False)
    def test_missing_resolv_conf_is_unknown_and_fails_safe(
        self, _exists, _service_active
    ) -> None:
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.UNKNOWN)
        self.assertFalse(status.safe_for_automatic_management)

    @patch("falak.core.environment._service_active", return_value=False)
    @patch("falak.core.environment.shutil.which", return_value=None)
    @patch("falak.core.environment.os.path.realpath")
    @patch("falak.core.environment.os.path.islink", return_value=True)
    @patch("falak.core.environment.os.path.exists", return_value=True)
    def test_symlink_to_unrecognized_target_is_unknown(
        self, _exists, _islink, mock_realpath, _which, _service_active
    ) -> None:
        mock_realpath.return_value = "/some/custom/dns-tool/resolv.conf"
        status = env._detect_dns()
        self.assertEqual(status.method, env.DnsMethod.UNKNOWN)
        self.assertFalse(status.safe_for_automatic_management)
        self.assertIn("unrecognized target", status.detail)

    @patch("falak.core.environment._service_active", return_value=False)
    @patch("falak.core.environment.os.path.exists", return_value=False)
    def test_unknown_dns_never_touches_filesystem_for_writing(
        self, _exists, _service_active
    ) -> None:
        # Regression guard: detection must never attempt to open
        # resolv.conf for writing, even in the fail-safe/unknown path.
        with patch("builtins.open") as mock_open:
            env._detect_dns()
            mock_open.assert_not_called()


# ---------------------------------------------------------------------------
# Route detection
# ---------------------------------------------------------------------------


class TestDetectRoutes(unittest.TestCase):
    @patch("falak.core.environment.shutil.which", return_value=None)
    def test_missing_ip_tool_marks_both_unavailable(self, _which) -> None:
        status = env._detect_routes()
        self.assertFalse(status.ipv4_available)
        self.assertFalse(status.ipv6_available)
        self.assertEqual(status.ipv4_default_routes, ())

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/sbin/ip")
    def test_successful_ipv4_and_ipv6_query(self, _which, mock_run) -> None:
        def side_effect(args, timeout=10.0, **kwargs):
            if "-4" in args:
                return CommandResult(
                    args=tuple(args),
                    returncode=0,
                    stdout="default via 192.168.1.1 dev eth0\n",
                    stderr="",
                )
            if "-6" in args:
                return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")
            raise AssertionError(f"unexpected args {args}")

        mock_run.side_effect = side_effect
        status = env._detect_routes()
        self.assertTrue(status.ipv4_available)
        self.assertTrue(status.ipv6_available)
        self.assertEqual(len(status.ipv4_default_routes), 1)
        self.assertEqual(status.ipv6_default_routes, ())

    @patch("falak.core.environment.run_command")
    @patch("falak.core.environment.shutil.which", return_value="/usr/sbin/ip")
    def test_ipv6_query_timeout_marks_only_ipv6_unavailable(self, _which, mock_run) -> None:
        def side_effect(args, timeout=10.0, **kwargs):
            if "-4" in args:
                return CommandResult(
                    args=tuple(args), returncode=0, stdout="default via 10.0.0.1 dev eth0\n", stderr=""
                )
            if "-6" in args:
                raise ShellError("timed out")
            raise AssertionError(f"unexpected args {args}")

        mock_run.side_effect = side_effect
        status = env._detect_routes()
        self.assertTrue(status.ipv4_available)
        self.assertFalse(status.ipv6_available)
        self.assertEqual(len(status.ipv4_default_routes), 1)


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------


class TestDetectEnvironment(unittest.TestCase):
    def test_warnings_include_missing_tool_and_unknown_dns(self) -> None:
        tools = (
            env.ToolStatus(name="wg", available=True, path="/usr/bin/wg"),
            env.ToolStatus(name="wg-quick", available=False),
            env.ToolStatus(name="ip", available=True, path="/usr/sbin/ip"),
            env.ToolStatus(name="nft", available=True, path="/usr/sbin/nft"),
        )
        nm = env.NetworkManagerStatus(installed=True, active=True, active_interfaces=("eth0",))
        dns = env.DnsStatus(
            method=env.DnsMethod.UNKNOWN,
            detail="unrecognized",
            safe_for_automatic_management=False,
        )
        routes = env.RouteStatus(
            ipv4_default_routes=(env.RouteEntry(gateway="10.0.0.1", interface="eth0", raw="default via 10.0.0.1 dev eth0"),),
            ipv6_default_routes=(),
            ipv4_available=True,
            ipv6_available=True,
        )

        with patch("falak.core.environment._detect_tools", return_value=tools), patch(
            "falak.core.environment._detect_network_manager", return_value=nm
        ), patch("falak.core.environment._detect_dns", return_value=dns), patch(
            "falak.core.environment._detect_routes", return_value=routes
        ):
            report = env.detect_environment()

        self.assertIn("Tool 'wg-quick' was not found on PATH.", report.warnings)
        self.assertTrue(
            any("DNS configuration could not be confidently classified" in w for w in report.warnings)
        )
        self.assertNotIn(
            "No IPv4 default route detected.", report.warnings
        )

    def test_no_ipv4_default_route_produces_warning(self) -> None:
        tools = (env.ToolStatus(name="wg", available=True, path="/usr/bin/wg"),)
        nm = env.NetworkManagerStatus(installed=True, active=True)
        dns = env.DnsStatus(method=env.DnsMethod.STATIC, detail="static")
        routes = env.RouteStatus(
            ipv4_default_routes=(),
            ipv6_default_routes=(),
            ipv4_available=True,
            ipv6_available=True,
        )

        with patch("falak.core.environment._detect_tools", return_value=tools), patch(
            "falak.core.environment._detect_network_manager", return_value=nm
        ), patch("falak.core.environment._detect_dns", return_value=dns), patch(
            "falak.core.environment._detect_routes", return_value=routes
        ):
            report = env.detect_environment()

        self.assertIn("No IPv4 default route detected.", report.warnings)

    def test_describe_contains_no_wireguard_key_material(self) -> None:
        # This module never touches WireGuard config/keys at all, so a
        # smoke test confirms describe() output has nothing resembling
        # key material in it (defense in depth, not a real scan).
        tools = (env.ToolStatus(name="wg", available=True, path="/usr/bin/wg"),)
        nm = env.NetworkManagerStatus(installed=False, active=None)
        dns = env.DnsStatus(method=env.DnsMethod.STATIC, detail="static")
        routes = env.RouteStatus(
            ipv4_default_routes=(), ipv6_default_routes=(), ipv4_available=True, ipv6_available=True
        )
        report = env.EnvironmentReport(tools=tools, network_manager=nm, dns=dns, routes=routes)
        summary = report.describe()
        self.assertNotIn("PrivateKey", summary)
        self.assertNotIn("PresharedKey", summary)

    def test_report_is_actually_read_only(self) -> None:
        # Full aggregate call, with only the external command runner and
        # filesystem probes mocked - confirms detect_environment() never
        # opens anything for writing.
        with patch("falak.core.environment.shutil.which", return_value=None), patch(
            "falak.core.environment.os.path.exists", return_value=False
        ), patch("falak.core.environment._service_active", return_value=None), patch(
            "builtins.open"
        ) as mock_open:
            env.detect_environment()
            mock_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
