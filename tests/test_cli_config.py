"""Unit tests for the `falak config` CLI command (Milestone 2.2)."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest

from falak.cli import main

FAKE_PRIVATE_KEY = "yAnz5TF8lXXJte14tji3zlMNq8hd2rYUIgJBgB3fBmk="
FAKE_PUBLIC_KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

VALID_CONFIG = f"""\
[Interface]
PrivateKey = {FAKE_PRIVATE_KEY}
Address = 10.8.0.2/24

[Peer]
PublicKey = {FAKE_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
"""


def _write_temp_config(contents: str, *, mode: int = 0o600) -> str:
    fd, path = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write(contents)
    os.chmod(path, mode)
    return path


class TestCliConfigValid(unittest.TestCase):
    def test_valid_config_prints_summary_and_returns_zero(self) -> None:
        path = _write_temp_config(VALID_CONFIG)
        try:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["config", path])
            self.assertEqual(exit_code, 0)
            output = stdout.getvalue()
            self.assertIn("Interface:", output)
            self.assertNotIn(FAKE_PRIVATE_KEY, output)
        finally:
            os.remove(path)


class TestCliConfigInvalid(unittest.TestCase):
    def test_missing_file_returns_nonzero_and_does_not_raise(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = main(["config", "/nonexistent/falak-test.conf"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Invalid configuration", stderr.getvalue())

    def test_malformed_config_returns_nonzero(self) -> None:
        path = _write_temp_config("[Interface]\nAddress = 10.8.0.2/24\n")
        try:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["config", path])
            self.assertEqual(exit_code, 1)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
