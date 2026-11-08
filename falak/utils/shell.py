"""
Safe subprocess execution wrapper for Falak.

Design rules (do not relax these without a deliberate security review):

  * Commands are always executed as an argument list, never as a shell
    string. ``shell=True`` is never used anywhere in this module.
  * The executable must exist on PATH (resolved via ``shutil.which``)
    before it is run. A missing binary fails with a clear error instead
    of a confusing OS-level exception.
  * Every call is timeout-bounded. A hung external command cannot hang
    Falak indefinitely.
  * Callers get back a structured ``CommandResult`` instead of raw
    subprocess internals, so calling code does not need to know
    subprocess details to use this safely.
  * This module performs no privilege escalation itself. If a command
    requires elevated privileges (e.g. ``ip``, ``wg-quick``), that is
    the caller's responsibility to request explicitly (e.g. via sudo),
    and will be addressed in a later milestone - not here.

This module has no networking, routing, DNS, or firewall logic. It only
knows how to run an already-decided command safely and report the
result.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence


class ShellError(Exception):
    """Base class for all errors raised by this module."""


class InvalidCommandError(ShellError):
    """Raised when the command arguments are malformed or unsafe."""


class CommandNotFoundError(ShellError):
    """Raised when the requested executable cannot be found on PATH."""


class CommandTimeoutError(ShellError):
    """Raised when a command does not complete within its timeout."""


@dataclass(frozen=True)
class CommandResult:
    """The outcome of a successfully-executed command.

    A ``CommandResult`` is only ever returned for a command that
    actually ran to completion (successfully or not). Commands that
    could not be run at all (bad arguments, missing binary, timeout)
    raise an exception instead of returning a result with a fake
    returncode.
    """

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """True if the command exited with status 0."""
        return self.returncode == 0


def _validate_args(args: Sequence[str]) -> tuple[str, ...]:
    """Validate that ``args`` is a safe, well-formed argument list.

    Raises InvalidCommandError if ``args`` is not a non-empty sequence
    of non-empty strings. This is intentionally strict: a single
    string (e.g. "wg-quick up wg0") is rejected, because passing it
    straight to subprocess without shell=True would be treated as one
    literal executable name, and passing it *with* shell=True is
    exactly the shell-injection risk this module exists to prevent.
    """
    if isinstance(args, (str, bytes)):
        raise InvalidCommandError(
            "Command must be a list of arguments, not a single string "
            "(e.g. ['wg-quick', 'up', 'wg0'], not 'wg-quick up wg0'). "
            "This prevents accidental shell interpretation."
        )

    try:
        materialized = list(args)
    except TypeError as exc:
        raise InvalidCommandError(
            f"Command must be a sequence of strings, got {type(args).__name__}."
        ) from exc

    if not materialized:
        raise InvalidCommandError("Command argument list must not be empty.")

    for item in materialized:
        if not isinstance(item, str):
            raise InvalidCommandError(
                f"All command arguments must be strings, got "
                f"{type(item).__name__}: {item!r}."
            )
        if item == "":
            raise InvalidCommandError(
                "Command arguments must not contain empty strings."
            )

    return tuple(materialized)


def run_command(
    args: Sequence[str],
    *,
    timeout: float = 10.0,
    check: bool = False,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command safely and return its result.

    Args:
        args: The command and its arguments as a list, e.g.
            ``["wg", "show"]``. Never a single shell string.
        timeout: Maximum time in seconds to wait for the command to
            complete before raising CommandTimeoutError.
        check: If True, raise ``subprocess.CalledProcessError`` when
            the command exits with a non-zero status. If False
            (default), a non-zero exit is returned in the
            ``CommandResult`` for the caller to inspect.
        input_text: Optional text to pipe to the command's stdin.

    Returns:
        A ``CommandResult`` describing the completed command.

    Raises:
        InvalidCommandError: ``args`` is malformed (see
            ``_validate_args``).
        CommandNotFoundError: The executable named in ``args[0]`` is
            not found on PATH.
        CommandTimeoutError: The command did not finish within
            ``timeout`` seconds.
        subprocess.CalledProcessError: ``check=True`` and the command
            returned a non-zero exit status.
    """
    validated = _validate_args(args)

    executable = shutil.which(validated[0])
    if executable is None:
        raise CommandNotFoundError(
            f"Required command '{validated[0]}' was not found on PATH. "
            f"It may not be installed."
        )

    try:
        completed = subprocess.run(  # noqa: S603 - args validated above, shell never used
            validated,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandTimeoutError(
            f"Command {' '.join(validated)!r} did not complete within "
            f"{timeout} seconds."
        ) from exc

    return CommandResult(
        args=validated,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
      )
