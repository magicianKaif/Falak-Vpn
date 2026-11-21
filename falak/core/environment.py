"""
Read-only environment detection for Falak.

Scope of this module (Milestone 2.3):

  * Detect whether required/supporting tools are installed
    (``wg``, ``wg-quick``, ``ip``, ``nft``).
  * Detect whether NetworkManager is installed and active, and which
    interfaces it currently reports as connected.
  * Identify which mechanism is currently managing DNS on this system
    (systemd-resolved, resolvconf, NetworkManager, a static file, or
    - explicitly - "unknown").
  * Inspect the current IPv4 and IPv6 default routes.
  * Assemble all of the above into a single, read-only
    ``EnvironmentReport``.

This module makes **no changes** of any kind:

  * No networking, routing, DNS, or firewall modification.
  * No service start/stop/restart.
  * No file writes (only ``/etc/resolv.conf`` is ever *read*, via
    ``os.path`` calls, never opened for writing).
  * No elevated privileges are requested or required - every command
    used here (``ip route show``, ``nmcli device status``,
    ``systemctl is-active``, ``wg --version``) is a standard read-only
    query runnable by an unprivileged user on Debian/Kali.

Fail-safe DNS handling: if the active DNS mechanism cannot be
confidently classified, this module reports ``DnsMethod.UNKNOWN``
with ``safe_for_automatic_management=False`` rather than guessing.
Nothing in this module (or any module it calls) edits
``/etc/resolv.conf`` under any circumstance - classification failure
simply means a later milestone (the adaptive DNS manager, 2.4) must
not attempt automatic DNS management on this system.

No WireGuard configuration, keys, or credentials are read or handled
anywhere in this module - environment detection is entirely
independent of ``falak.config.loader``.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from enum import Enum

from falak.utils.logger import get_logger
from falak.utils.shell import ShellError, run_command

logger = get_logger("falak.environment")

_RESOLV_CONF_PATH = "/etc/resolv.conf"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class DnsMethod(str, Enum):
    SYSTEMD_RESOLVED = "systemd-resolved"
    RESOLVCONF = "resolvconf"
    NETWORK_MANAGER = "network-manager"
    STATIC = "static"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolStatus:
    """Availability (and, best-effort, version) of a single external tool."""

    name: str
    available: bool
    path: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class NetworkManagerStatus:
    """What was observed about NetworkManager, read-only."""

    installed: bool
    active: bool | None  # None = installed but activity could not be confirmed
    active_interfaces: tuple[str, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class DnsStatus:
    """The detected DNS management mechanism.

    ``safe_for_automatic_management`` is False only for
    ``DnsMethod.UNKNOWN`` - it exists so later milestones have a
    single, explicit flag to check rather than re-deriving "is this
    method one we understand" from the enum value themselves.
    """

    method: DnsMethod
    detail: str
    resolv_conf_is_symlink: bool = False
    resolv_conf_target: str | None = None
    safe_for_automatic_management: bool = True


@dataclass(frozen=True)
class RouteEntry:
    """A single parsed default-route line from `ip route show default`."""

    gateway: str | None
    interface: str | None
    raw: str


@dataclass(frozen=True)
class RouteStatus:
    """Current default routes, IPv4 and IPv6, as observed read-only."""

    ipv4_default_routes: tuple[RouteEntry, ...]
    ipv6_default_routes: tuple[RouteEntry, ...]
    ipv4_available: bool  # False only if the routing table could not be queried
    ipv6_available: bool
    detail: str = ""


@dataclass(frozen=True)
class EnvironmentReport:
    """The complete, read-only environment snapshot."""

    tools: tuple[ToolStatus, ...]
    network_manager: NetworkManagerStatus
    dns: DnsStatus
    routes: RouteStatus
    warnings: tuple[str, ...] = ()

    def tool(self, name: str) -> ToolStatus | None:
        """Look up a single tool's status by name."""
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def describe(self) -> str:
        """Human-readable summary. Contains no secrets - this report
        never touches WireGuard key material in the first place."""
        lines: list[str] = ["Tools:"]
        for t in self.tools:
            if t.available:
                version = f" ({t.version})" if t.version else ""
                lines.append(f"  {t.name}: available at {t.path}{version}")
            else:
                lines.append(f"  {t.name}: NOT FOUND")

        lines.append("NetworkManager:")
        nm = self.network_manager
        if not nm.installed:
            lines.append("  Not installed (nmcli not found).")
        else:
            active_str = (
                "active" if nm.active is True
                else "inactive" if nm.active is False
                else "unknown"
            )
            lines.append(f"  Installed, service state: {active_str}")
            lines.append(
                f"  Active interfaces: {', '.join(nm.active_interfaces) or '(none observed)'}"
            )
        if nm.detail:
            lines.append(f"  Detail: {nm.detail}")

        lines.append("DNS:")
        lines.append(f"  Method: {self.dns.method.value}")
        lines.append(f"  Detail: {self.dns.detail}")
        if not self.dns.safe_for_automatic_management:
            lines.append(
                "  Automatic DNS management: DISABLED (configuration not "
                "confidently recognized - no DNS changes will be made)."
            )

        lines.append("Routes:")
        lines.append(
            "  IPv4 default: "
            + (
                "; ".join(r.raw for r in self.routes.ipv4_default_routes)
                if self.routes.ipv4_default_routes
                else "(none)" if self.routes.ipv4_available else "(could not query)"
            )
        )
        lines.append(
            "  IPv6 default: "
            + (
                "; ".join(r.raw for r in self.routes.ipv6_default_routes)
                if self.routes.ipv6_default_routes
                else "(none)" if self.routes.ipv6_available else "(could not query)"
            )
        )

        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  - {w}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------


def _detect_tool(name: str, version_args: tuple[str, ...] | None) -> ToolStatus:
    path = shutil.which(name)
    if path is None:
        return ToolStatus(name=name, available=False)

    version: str | None = None
    if version_args:
        try:
            result = run_command([name, *version_args], timeout=5)
            text = (result.stdout or result.stderr).strip()
            version = text.splitlines()[0] if text else None
        except ShellError as exc:
            logger.debug("Version probe for %s failed (non-fatal): %s", name, exc)

    return ToolStatus(name=name, available=True, path=path, version=version)


def _detect_tools() -> tuple[ToolStatus, ...]:
    return (
        _detect_tool("wg", version_args=("--version",)),
        _detect_tool("wg-quick", version_args=None),
        _detect_tool("ip", version_args=("-V",)),
        _detect_tool("nft", version_args=("--version",)),
    )


# ---------------------------------------------------------------------------
# systemd service helper
# ---------------------------------------------------------------------------


def _service_active(service_name: str) -> bool | None:
    """Return True/False if systemctl can confirm active state, else None."""
    if shutil.which("systemctl") is None:
        return None
    try:
        result = run_command(["systemctl", "is-active", service_name], timeout=5)
    except ShellError as exc:
        logger.debug("systemctl is-active %s failed: %s", service_name, exc)
        return None
    return result.stdout.strip() == "active"


# ---------------------------------------------------------------------------
# NetworkManager detection
# ---------------------------------------------------------------------------


def _detect_network_manager() -> NetworkManagerStatus:
    if shutil.which("nmcli") is None:
        return NetworkManagerStatus(
            installed=False,
            active=None,
            detail="nmcli not found on PATH; NetworkManager does not appear to be installed.",
        )

    detail_parts: list[str] = []
    active = _service_active("NetworkManager")
    if active is None:
        detail_parts.append(
            "Could not confirm service state via systemctl; falling back to nmcli reachability."
        )
    else:
        detail_parts.append(f"systemctl reports NetworkManager service active={active}.")

    active_interfaces: tuple[str, ...] = ()
    try:
        result = run_command(
            ["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status"],
            timeout=5,
        )
        if result.ok:
            interfaces = []
            for line in result.stdout.splitlines():
                fields = line.split(":")
                if len(fields) >= 2 and fields[1] == "connected":
                    interfaces.append(fields[0])
            active_interfaces = tuple(interfaces)
            if active is None:
                # nmcli answered successfully, so NM is at least reachable.
                active = True
        else:
            detail_parts.append(
                f"'nmcli device status' exited {result.returncode}: {result.stderr.strip()}"
            )
    except ShellError as exc:
        detail_parts.append(f"Could not query 'nmcli device status': {exc}")

    return NetworkManagerStatus(
        installed=True,
        active=active,
        active_interfaces=active_interfaces,
        detail=" ".join(detail_parts),
    )


# ---------------------------------------------------------------------------
# DNS detection (adaptive, fail-safe)
# ---------------------------------------------------------------------------


def _detect_dns() -> DnsStatus:
    exists = os.path.exists(_RESOLV_CONF_PATH)
    is_symlink = os.path.islink(_RESOLV_CONF_PATH)
    target: str | None = None
    if exists:
        try:
            target = os.path.realpath(_RESOLV_CONF_PATH)
        except OSError as exc:
            logger.debug("Could not resolve realpath of resolv.conf: %s", exc)

    # 1. systemd-resolved - canonical signature is the stub-resolv.conf
    #    (or resolve/resolv.conf) symlink target, corroborated by the
    #    service being active where that can be confirmed.
    if target and "systemd" in target and "resolve" in target:
        return DnsStatus(
            method=DnsMethod.SYSTEMD_RESOLVED,
            detail=f"{_RESOLV_CONF_PATH} -> {target} (systemd-resolved stub resolver).",
            resolv_conf_is_symlink=is_symlink,
            resolv_conf_target=target,
            safe_for_automatic_management=True,
        )
    systemd_active = _service_active("systemd-resolved")
    if systemd_active is True:
        return DnsStatus(
            method=DnsMethod.SYSTEMD_RESOLVED,
            detail=(
                "systemd-resolved service is active (confirmed via systemctl), "
                f"though {_RESOLV_CONF_PATH} does not point at its usual stub path."
            ),
            resolv_conf_is_symlink=is_symlink,
            resolv_conf_target=target,
            safe_for_automatic_management=True,
        )

    # 2. resolvconf
    if target and "resolvconf" in target:
        return DnsStatus(
            method=DnsMethod.RESOLVCONF,
            detail=f"{_RESOLV_CONF_PATH} -> {target} (managed by resolvconf).",
            resolv_conf_is_symlink=is_symlink,
            resolv_conf_target=target,
            safe_for_automatic_management=True,
        )
    if shutil.which("resolvconf") is not None and os.path.isdir("/etc/resolvconf"):
        return DnsStatus(
            method=DnsMethod.RESOLVCONF,
            detail=(
                "resolvconf binary and /etc/resolvconf directory are present, "
                f"though {_RESOLV_CONF_PATH}'s target does not explicitly name it."
            ),
            resolv_conf_is_symlink=is_symlink,
            resolv_conf_target=target,
            safe_for_automatic_management=True,
        )

    # 3. NetworkManager-managed DNS
    if target and "networkmanager" in target.lower():
        return DnsStatus(
            method=DnsMethod.NETWORK_MANAGER,
            detail=f"{_RESOLV_CONF_PATH} -> {target} (managed by NetworkManager).",
            resolv_conf_is_symlink=is_symlink,
            resolv_conf_target=target,
            safe_for_automatic_management=True,
        )

    # 4. Static: a real, non-symlink file.
    if exists and not is_symlink:
        return DnsStatus(
            method=DnsMethod.STATIC,
            detail=(
                f"{_RESOLV_CONF_PATH} is a regular file (not a symlink) and no "
                f"known DNS manager service was confirmed active - treated as "
                f"static configuration."
            ),
            resolv_conf_is_symlink=False,
            resolv_conf_target=None,
            safe_for_automatic_management=True,
        )

    # 5. Fail-safe: anything else is explicitly UNKNOWN. This includes a
    #    missing resolv.conf, or a symlink to a target this function does
    #    not recognize. No DNS modification is ever attempted here or
    #    anywhere downstream when this is returned.
    if not exists:
        reason = f"{_RESOLV_CONF_PATH} does not exist."
    elif is_symlink:
        reason = f"{_RESOLV_CONF_PATH} is a symlink to an unrecognized target: {target}."
    else:
        reason = f"{_RESOLV_CONF_PATH} state could not be classified."

    return DnsStatus(
        method=DnsMethod.UNKNOWN,
        detail=(
            f"{reason} No known DNS manager (systemd-resolved, resolvconf, "
            f"NetworkManager) was confirmed, and the file does not match a "
            f"plain static configuration either. Falak will NOT attempt any "
            f"automatic DNS management on this system."
        ),
        resolv_conf_is_symlink=is_symlink,
        resolv_conf_target=target,
        safe_for_automatic_management=False,
    )


# ---------------------------------------------------------------------------
# Route detection
# ---------------------------------------------------------------------------


def _parse_default_route_lines(output: str) -> tuple[RouteEntry, ...]:
    entries: list[RouteEntry] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("default"):
            continue
        tokens = line.split()
        gateway: str | None = None
        interface: str | None = None
        if "via" in tokens:
            idx = tokens.index("via")
            if idx + 1 < len(tokens):
                gateway = tokens[idx + 1]
        if "dev" in tokens:
            idx = tokens.index("dev")
            if idx + 1 < len(tokens):
                interface = tokens[idx + 1]
        entries.append(RouteEntry(gateway=gateway, interface=interface, raw=line))
    return tuple(entries)


def _detect_routes() -> RouteStatus:
    if shutil.which("ip") is None:
        return RouteStatus(
            ipv4_default_routes=(),
            ipv6_default_routes=(),
            ipv4_available=False,
            ipv6_available=False,
            detail="'ip' command not found; cannot inspect routing table.",
        )

    detail_parts: list[str] = []

    ipv4_routes: tuple[RouteEntry, ...] = ()
    ipv4_available = True
    try:
        result = run_command(["ip", "-4", "route", "show", "default"], timeout=5)
        ipv4_routes = _parse_default_route_lines(result.stdout)
        if not result.ok:
            detail_parts.append(
                f"'ip -4 route show default' exited {result.returncode}: {result.stderr.strip()}"
            )
    except ShellError as exc:
        ipv4_available = False
        detail_parts.append(f"Could not query IPv4 default route: {exc}")

    ipv6_routes: tuple[RouteEntry, ...] = ()
    ipv6_available = True
    try:
        result = run_command(["ip", "-6", "route", "show", "default"], timeout=5)
        ipv6_routes = _parse_default_route_lines(result.stdout)
        if not result.ok:
            detail_parts.append(
                f"'ip -6 route show default' exited {result.returncode}: {result.stderr.strip()}"
            )
    except ShellError as exc:
        ipv6_available = False
        detail_parts.append(f"Could not query IPv6 default route: {exc}")

    return RouteStatus(
        ipv4_default_routes=ipv4_routes,
        ipv6_default_routes=ipv6_routes,
        ipv4_available=ipv4_available,
        ipv6_available=ipv6_available,
        detail=" ".join(detail_parts),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_environment() -> EnvironmentReport:
    """Produce a complete, read-only snapshot of the current environment.

    This function performs no writes, no privileged operations, and no
    modification of networking/DNS/firewall state. Every sub-detector
    is independently fault-tolerant: a failure probing one piece of
    the environment (e.g. `nft` missing, or `ip` timing out) is
    recorded as a warning and never prevents the rest of the report
    from being produced.
    """
    warnings: list[str] = []

    tools = _detect_tools()
    for tool in tools:
        if not tool.available:
            warnings.append(f"Tool '{tool.name}' was not found on PATH.")

    nm_status = _detect_network_manager()
    if not nm_status.installed:
        warnings.append(
            "NetworkManager (nmcli) not found; Falak cannot verify that "
            "existing NM-managed connectivity will be preserved."
        )

    dns_status = _detect_dns()
    if dns_status.method is DnsMethod.UNKNOWN:
        warnings.append(
            "DNS configuration could not be confidently classified - "
            "automatic DNS management is disabled for safety."
        )

    route_status = _detect_routes()
    if not route_status.ipv4_available and not route_status.ipv6_available:
        warnings.append(
            "Could not inspect the routing table ('ip' command unavailable "
            "or failed for both IPv4 and IPv6)."
        )
    elif route_status.ipv4_available and not route_status.ipv4_default_routes:
        warnings.append("No IPv4 default route detected.")
    # No IPv6 default route is common and benign (many networks are
    # IPv4-only) - not flagged as a warning on its own.

    return EnvironmentReport(
        tools=tools,
        network_manager=nm_status,
        dns=dns_status,
        routes=route_status,
        warnings=tuple(warnings),
    )
