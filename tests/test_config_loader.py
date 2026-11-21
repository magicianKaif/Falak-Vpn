"""Unit tests for falak.config.loader."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest

from falak.config.loader import (
    ConfigNotFoundError,
    ConfigUnsafeForConnectionError,
    ConfigValidationError,
    ensure_safe_for_connection,
    load_config,
)

# Syntactically valid-shaped WireGuard keys for test purposes only
# (44 chars, base64 charset, trailing '='). Not real keys.
FAKE_PRIVATE_KEY = "yAnz5TF8lXXJte14tji3zlMNq8hd2rYUIgJBgB3fBmk="
FAKE_PUBLIC_KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
FAKE_PSK = "FpCyhws3ab9u1BppKnVWnB5pWInNRCl2Y5TeOK5rvF0="

VALID_CONFIG = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
DNS = 1.1.1.1, 1.0.0.1
MTU = 1420

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""


def _write_temp_config(contents: str, *, mode: int = 0o600) -> str:
    fd, path = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write(contents)
    os.chmod(path, mode)
    return path


class TestLoadConfigValid(unittest.TestCase):
    def setUp(self) -> None:
        self.path = _write_temp_config(VALID_CONFIG)

    def tearDown(self) -> None:
        os.remove(self.path)

    def test_parses_interface_fields(self) -> None:
        config = load_config(self.path)
        self.assertEqual(config.interface.address, ("10.8.0.2/24",))
        self.assertEqual(config.interface.dns, ("1.1.1.1", "1.0.0.1"))
        self.assertEqual(config.interface.mtu, 1420)
        self.assertEqual(config.interface.private_key, FAKE_PRIVATE_KEY)

    def test_parses_single_peer(self) -> None:
        config = load_config(self.path)
        self.assertEqual(len(config.peers), 1)
        peer = config.peers[0]
        self.assertEqual(peer.public_key, FAKE_PUBLIC_KEY)
        self.assertEqual(peer.allowed_ips, ("0.0.0.0/0",))
        self.assertEqual(peer.endpoint, "vpn.example.com:51820")
        self.assertEqual(peer.persistent_keepalive, 25)
        self.assertFalse(peer.has_preshared_key)

    def test_no_permission_warning_on_0600(self) -> None:
        config = load_config(self.path)
        self.assertEqual(config.warnings, ())

    def test_describe_never_includes_private_key(self) -> None:
        config = load_config(self.path)
        summary = config.describe()
        self.assertNotIn(FAKE_PRIVATE_KEY, summary)
        self.assertIn("REDACTED", summary)

    def test_describe_includes_public_key(self) -> None:
        # Public keys are not secret and are useful to display.
        config = load_config(self.path)
        self.assertIn(FAKE_PUBLIC_KEY, config.describe())

    def test_str_of_interface_never_leaks_private_key(self) -> None:
        config = load_config(self.path)
        self.assertNotIn(FAKE_PRIVATE_KEY, str(config.interface))
        self.assertNotIn(FAKE_PRIVATE_KEY, repr(config.interface))


class TestLoadConfigMultiplePeers(unittest.TestCase):
    def test_multiple_peer_sections_are_all_parsed(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 10.8.0.0/24

[Peer]
PublicKey = {FAKE_PSK}
AllowedIPs = 10.9.0.0/24
PresharedKey = {FAKE_PSK}
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(len(config.peers), 2)
            self.assertFalse(config.peers[0].has_preshared_key)
            self.assertTrue(config.peers[1].has_preshared_key)
        finally:
            os.remove(path)


class TestLoadConfigPresharedKeyNotRetained(unittest.TestCase):
    def test_preshared_key_value_not_stored_on_peer_object(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
PresharedKey = {FAKE_PSK}
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            peer = config.peers[0]
            self.assertTrue(peer.has_preshared_key)
            # The PeerConfig dataclass has no field at all capable of
            # holding the raw value - confirm it genuinely isn't
            # reachable from the returned object.
            peer_values = vars(peer).values()
            self.assertNotIn(FAKE_PSK, peer_values)
        finally:
            os.remove(path)


class TestLoadConfigHookWarning(unittest.TestCase):
    def test_hook_directives_produce_warning(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertTrue(config.interface.has_hook_directives)
            self.assertTrue(
                any("PreUp/PostUp" in w for w in config.warnings)
            )
        finally:
            os.remove(path)


class TestLoadConfigPermissionsWarning(unittest.TestCase):
    def test_world_readable_file_produces_warning(self) -> None:
        path = _write_temp_config(VALID_CONFIG, mode=0o644)
        try:
            config = load_config(path)
            self.assertTrue(
                any("permissions" in w.lower() for w in config.warnings)
            )
        finally:
            os.remove(path)

    def test_permissions_are_never_modified(self) -> None:
        path = _write_temp_config(VALID_CONFIG, mode=0o644)
        try:
            before = stat.S_IMODE(os.stat(path).st_mode)
            load_config(path)
            after = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(before, after)
        finally:
            os.remove(path)


class TestLoadConfigErrors(unittest.TestCase):
    def test_missing_file_raises_not_found(self) -> None:
        with self.assertRaises(ConfigNotFoundError):
            load_config("/nonexistent/path/falak-test.conf")

    def test_missing_interface_section_raises(self) -> None:
        text = f"""\
[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_missing_peer_section_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_malformed_private_key_raises(self) -> None:
        text = """\
[Interface]
PrivateKey = not-a-real-key
Address = 10.8.0.2/24

[Peer]
PublicKey = """ + FAKE_PUBLIC_KEY + """
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_malformed_private_key_value_not_in_error_message(self) -> None:
        bad_key = "totally-not-base64-and-wrong-length"
        text = f"""\
[Interface]
PrivateKey = {bad_key}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError) as ctx:
                load_config(path)
            self.assertNotIn(bad_key, str(ctx.exception))
        finally:
            os.remove(path)

    def test_invalid_address_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = not-an-ip

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_invalid_allowed_ips_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = garbage
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_invalid_endpoint_port_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:999999
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_ipv6_endpoint_is_accepted(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = [2001:db8::1]:51820
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(config.peers[0].endpoint, "[2001:db8::1]:51820")
        finally:
            os.remove(path)

    def test_duplicate_interface_section_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.3/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_duplicate_key_in_section_raises(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_key_value_before_section_raises(self) -> None:
        text = f"PrivateKey = {FAKE_PRIVATE_KEY}\n[Interface]\nAddress = 10.8.0.2/24\n"
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_unrecognized_key_is_warning_not_error(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
SomeFutureDirective = hello

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertTrue(
                any("SomeFutureDirective" in w for w in config.warnings)
            )
        finally:
            os.remove(path)


class TestLoadConfigNeverWrites(unittest.TestCase):
    def test_file_contents_unchanged_after_load(self) -> None:
        path = _write_temp_config(VALID_CONFIG)
        try:
            with open(path, "r", encoding="utf-8") as f:
                before = f.read()
            load_config(path)
            with open(path, "r", encoding="utf-8") as f:
                after = f.read()
            self.assertEqual(before, after)
        finally:
            os.remove(path)


class TestListenPortZeroValue(unittest.TestCase):
    """ListenPort = 0 means 'choose randomly' per wg(8) - must be accepted."""

    def test_listen_port_zero_is_accepted(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
ListenPort = 0

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(config.interface.listen_port, 0)
        finally:
            os.remove(path)

    def test_listen_port_zero_displays_as_zero_not_as_unset(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
ListenPort = 0

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertIn("ListenPort: 0", config.describe())
            self.assertNotIn("(default/random)", config.describe())
        finally:
            os.remove(path)

    def test_listen_port_negative_still_rejected(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
ListenPort = -1

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_listen_port_above_65535_still_rejected(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
ListenPort = 70000

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)


class TestPersistentKeepaliveZeroValue(unittest.TestCase):
    """PersistentKeepalive = 0 explicitly disables it per wg(8) - must be accepted."""

    def test_persistent_keepalive_zero_is_accepted(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(config.peers[0].persistent_keepalive, 0)
        finally:
            os.remove(path)

    def test_persistent_keepalive_zero_displays_as_zero_not_as_off(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertIn("PersistentKeepalive: 0", config.describe())
        finally:
            os.remove(path)

    def test_persistent_keepalive_above_65535_still_rejected(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 100000
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)


class TestDnsEmptyEntriesRejected(unittest.TestCase):
    def test_dns_with_only_commas_is_rejected(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
DNS = , ,

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_dns_with_single_comma_is_rejected(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
DNS = ,

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_dns_with_real_entry_among_empties_is_still_accepted(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
DNS = , 1.1.1.1 ,

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(config.interface.dns, ("1.1.1.1",))
        finally:
            os.remove(path)


class TestSemicolonIsNotAComment(unittest.TestCase):
    """Per wg(8): only '#' is a comment delimiter. ';' must be treated as
    ordinary data, not silently stripped."""

    def test_semicolon_prefixed_line_is_not_silently_ignored(self) -> None:
        # Under the old (incorrect) behavior this line would have been
        # silently treated as a comment and ignored. Under correct
        # wg(8) semantics it is an invalid key-value line and must be
        # rejected loudly, not swallowed.
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
; this looks like a comment but is not one per wg(8)

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            with self.assertRaises(ConfigValidationError):
                load_config(path)
        finally:
            os.remove(path)

    def test_hash_comment_is_still_stripped(self) -> None:
        # Regression guard: the real comment character must still work.
        text = f"""\
[Interface]
# this is a real comment
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24  # trailing comment too

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            self.assertEqual(config.interface.address, ("10.8.0.2/24",))
        finally:
            os.remove(path)


class TestEnsureSafeForConnection(unittest.TestCase):
    def test_raises_when_hooks_present_and_not_acknowledged(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            with self.assertRaises(ConfigUnsafeForConnectionError):
                ensure_safe_for_connection(config)
        finally:
            os.remove(path)

    def test_passes_when_hooks_present_and_explicitly_acknowledged(self) -> None:
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            # Should not raise.
            ensure_safe_for_connection(config, acknowledge_hooks=True)
        finally:
            os.remove(path)

    def test_passes_when_no_hooks_present(self) -> None:
        path = _write_temp_config(VALID_CONFIG)
        try:
            config = load_config(path)
            # Should not raise, even with the default acknowledge_hooks=False.
            ensure_safe_for_connection(config)
        finally:
            os.remove(path)

    def test_default_is_fail_closed(self) -> None:
        # Regression guard: calling with no keyword argument at all
        # must be the safe (rejecting) behavior when hooks are present.
        text = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24
PreDown = echo teardown

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""
        path = _write_temp_config(text)
        try:
            config = load_config(path)
            with self.assertRaises(ConfigUnsafeForConnectionError):
                ensure_safe_for_connection(config)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
