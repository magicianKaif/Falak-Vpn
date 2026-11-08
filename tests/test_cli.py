"""Unit tests for falak.cli."""

from __future__ import annotations

import contextlib
import io
import unittest

from falak import __version__
from falak.cli import main


class TestCliVersion(unittest.TestCase):
    def test_version_command_prints_version_and_returns_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["version"])

        self.assertEqual(exit_code, 0)
        self.assertIn(__version__, stdout.getvalue())


class TestCliHelp(unittest.TestCase):
    def test_help_flag_exits_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as ctx:
                main(["--help"])

        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("falak", stdout.getvalue())

    def test_no_arguments_prints_help_and_returns_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main([])

        self.assertEqual(exit_code, 0)
        self.assertIn("usage", stdout.getvalue().lower())


class TestCliUnknownCommand(unittest.TestCase):
    def test_unknown_command_exits_nonzero(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                main(["not-a-real-command"])

        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
