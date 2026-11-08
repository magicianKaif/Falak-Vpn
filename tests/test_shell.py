"""Unit tests for falak.utils.shell."""

from __future__ import annotations

import subprocess
import sys
import unittest

from falak.utils.shell import (
    CommandNotFoundError,
    CommandResult,
    CommandTimeoutError,
    InvalidCommandError,
    run_command,
)

# Use the interpreter running the tests as a guaranteed-present
# executable, rather than depending on any particular OS utility
# being installed in the test environment.
PYTHON = sys.executable


class TestRunCommandSuccess(unittest.TestCase):
    def test_successful_command_returns_result(self) -> None:
        result = run_command([PYTHON, "-c", "print('hello')"])
        self.assertIsInstance(result, CommandResult)
        self.assertTrue(result.ok)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "hello")

    def test_nonzero_exit_without_check_is_not_an_error(self) -> None:
        result = run_command([PYTHON, "-c", "import sys; sys.exit(3)"], check=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 3)

    def test_check_true_raises_on_nonzero_exit(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            run_command([PYTHON, "-c", "import sys; sys.exit(1)"], check=True)

    def test_input_text_is_passed_to_stdin(self) -> None:
        result = run_command(
            [PYTHON, "-c", "import sys; print(sys.stdin.read().strip())"],
            input_text="piped-value",
        )
        self.assertEqual(result.stdout.strip(), "piped-value")

    def test_result_args_reflects_input(self) -> None:
        result = run_command([PYTHON, "-c", "pass"])
        self.assertEqual(result.args, (PYTHON, "-c", "pass"))


class TestRunCommandValidation(unittest.TestCase):
    def test_string_instead_of_list_is_rejected(self) -> None:
        with self.assertRaises(InvalidCommandError):
            run_command("echo hello")  # type: ignore[arg-type]

    def test_empty_list_is_rejected(self) -> None:
        with self.assertRaises(InvalidCommandError):
            run_command([])

    def test_non_string_argument_is_rejected(self) -> None:
        with self.assertRaises(InvalidCommandError):
            run_command([PYTHON, 123])  # type: ignore[list-item]

    def test_empty_string_argument_is_rejected(self) -> None:
        with self.assertRaises(InvalidCommandError):
            run_command([PYTHON, ""])

    def test_shell_true_is_never_used(self) -> None:
        # Regression guard: even a string that LOOKS like a safe
        # command must never be executed via a shell.
        with self.assertRaises(InvalidCommandError):
            run_command("rm -rf /tmp/does-not-exist; echo pwned")  # type: ignore[arg-type]


class TestRunCommandExecutableResolution(unittest.TestCase):
    def test_missing_executable_raises_not_found(self) -> None:
        with self.assertRaises(CommandNotFoundError):
            run_command(["falak-definitely-not-a-real-binary-xyz"])


class TestRunCommandTimeout(unittest.TestCase):
    def test_timeout_raises_command_timeout_error(self) -> None:
        with self.assertRaises(CommandTimeoutError):
            run_command(
                [PYTHON, "-c", "import time; time.sleep(5)"],
                timeout=0.2,
            )


if __name__ == "__main__":
    unittest.main()
