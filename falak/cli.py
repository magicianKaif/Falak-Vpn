"""
Falak CLI entry point.

Milestone 2.1 scope only: an argparse-based skeleton exposing
``falak --help`` and ``falak version``. No networking, routing, DNS,
or firewall commands exist yet, and nothing in this module requires
elevated privileges.

Later milestones will add subcommands (``config``, ``status``,
``connect``, ``disconnect``, ``diagnostics``) without changing this
file's basic structure: each subcommand gets its own handler function
and is registered with its own subparser.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from falak import __version__
from falak.config.loader import ConfigError, load_config
from falak.core.environment import detect_environment
from falak.utils.logger import get_logger

logger = get_logger("falak.cli")


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse parser and its subcommands."""
    parser = argparse.ArgumentParser(
        prog="falak",
        description=(
            "Falak - a personal WireGuard VPN client for Debian/Kali "
            "Linux. (Development build: no connect/disconnect "
            "functionality is implemented yet.)"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<command>",
    )

    subparsers.add_parser(
        "version",
        help="Show the Falak version and exit.",
    )

    config_parser = subparsers.add_parser(
        "config",
        help="Parse and validate a WireGuard .conf file (read-only).",
    )
    config_parser.add_argument(
        "path",
        help="Path to the WireGuard configuration file to validate.",
    )

    subparsers.add_parser(
        "status",
        help=(
            "Show a read-only environment report (tools, NetworkManager, "
            "DNS method, default routes). Makes no changes."
        ),
    )

    return parser


def _handle_version(_args: argparse.Namespace) -> int:
    """Handle `falak version`."""
    print(f"falak {__version__}")
    return 0


def _handle_config(args: argparse.Namespace) -> int:
    """Handle `falak config <path>`.

    Read-only: parses and validates the given WireGuard .conf file and
    prints a redacted summary. Never establishes a connection, never
    modifies the file, and never prints PrivateKey/PresharedKey values.
    """
    try:
        config = load_config(args.path)
    except ConfigError as exc:
        logger.error("Configuration invalid: %s", exc)
        print(f"Invalid configuration: {exc}", file=sys.stderr)
        return 1

    print(config.describe())
    return 0


def _handle_status(_args: argparse.Namespace) -> int:
    """Handle `falak status`.

    Read-only: probes tool availability, NetworkManager, DNS method,
    and default routes, then prints a summary. Never modifies
    networking, DNS, routes, or firewall state, and never touches
    WireGuard config or key material.
    """
    report = detect_environment()
    print(report.describe())
    return 0


_COMMAND_HANDLERS = {
    "version": _handle_version,
    "config": _handle_config,
    "status": _handle_status,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Falak CLI.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``
            when ``None`` (the normal case for a real invocation);
            tests pass an explicit list instead.

    Returns:
        Process exit code: 0 on success, non-zero on error.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # No subcommand given: show help, matching common CLI
        # convention, and exit with a non-error status.
        parser.print_help()
        return 0

    handler = _COMMAND_HANDLERS.get(args.command)
    if handler is None:
        # Should be unreachable because argparse restricts `command`
        # to registered subparsers, but handled explicitly rather
        # than silently doing nothing.
        logger.error("No handler registered for command: %s", args.command)
        return 1

    try:
        return handler(args)
    except Exception:  # noqa: BLE001 - top-level CLI boundary
        logger.exception("Unhandled error while running '%s'", args.command)
        return 1


if __name__ == "__main__":
    sys.exit(main())
