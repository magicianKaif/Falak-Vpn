"""
Falak VPN - a personal WireGuard VPN client for Debian/Kali Linux.

This package is being built incrementally. Milestone 2.1 provides only:
  - a safe subprocess execution wrapper (no shell, argument lists only)
  - basic logging with secret redaction
  - an argparse-based CLI skeleton (--help, version)

No networking, routing, DNS, or firewall modifications are implemented
yet. See README.md / project context for the full roadmap and current
scope.
"""

__all__ = ["__version__"]

__version__: str = "0.1.0-dev"
