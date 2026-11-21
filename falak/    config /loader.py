"""
WireGuard configuration parsing and read-only validation for Falak.

Scope of this module (Milestone 2.2):

  * Read a WireGuard ``.conf`` file from disk and parse its
    ``[Interface]`` / ``[Peer]`` sections.
  * Validate structure and syntax: required keys present, key material
    has the correct base64 shape, addresses/CIDRs/ports parse
    correctly.
  * Report (not fix) file-permission issues.
  * Report (not execute) risky directives such as ``PreUp``/``PostUp``
    hook scripts, so the user is aware they exist before any later
    milestone ever passes this file to ``wg-quick``.
  * Provide ``ensure_safe_for_connection()``: a fail-closed gate that
    a future connection milestone (2.5) must call before invoking
    ``wg-quick`` - it raises ``ConfigUnsafeForConnectionError`` for a
    config containing hook directives unless the caller explicitly
    acknowledges them. This module does not call it itself and does
    not connect to anything; it only prepares the gate for later use.

This module does **not**:

  * Establish any connection.
  * Modify the filesystem, networking, routing, DNS, or firewall state.
  * Modify the configuration file's permissions or contents.
  * Cryptographically verify that a private key is a valid Curve25519
    scalar, or that a public key corresponds to any private key.
    Validation here is syntactic only (base64 shape/length) - see
    SECURITY_NOTES.md for why, and what that does and does not
    guarantee.

The raw ``PrivateKey`` and ``PresharedKey`` values are held in memory
only as long as the returned ``WireGuardConfig`` object exists, are
never written anywhere, and are never included in any exception
message, log line, or CLI summary (which calls ``.describe()``,
specifically designed to omit them).
"""

from __future__ import annotations

import ipaddress
import os
import stat
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    """Base class for all errors raised by this module."""


class ConfigNotFoundError(ConfigError):
    """Raised when the configuration file does not exist."""


class ConfigPermissionError(ConfigError):
    """Raised when the configuration file cannot be read."""


class ConfigValidationError(ConfigError):
    """Raised when the configuration file is structurally invalid.

    Messages reference line numbers and the *name* of the offending
    key only - never the raw line content - so a malformed
    ``PrivateKey`` line can never have its value echoed back in an
    error message, a log, or a CLI failure output.
    """


class ConfigUnsafeForConnectionError(ConfigError):
    """Raised by ``ensure_safe_for_connection`` - see that function.

    This is distinct from ``ConfigValidationError``: a config raising
    this is syntactically valid and safe to *parse and display*, but
    is not safe to hand to ``wg-quick`` without explicit human review,
    because it contains PreUp/PostUp/PreDown/PostDown hook directives
    that wg-quick will execute as shell commands.
    """


# ---------------------------------------------------------------------------
# Known directives
# ---------------------------------------------------------------------------

# A syntactically valid WireGuard key: 32 raw bytes, base64-encoded,
# always 43 characters followed by one '=' padding character. This is
# a SYNTAX check only - it does not confirm the value is a valid
# Curve25519 scalar. See SECURITY_NOTES.md.
_KEY_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _looks_like_wg_key(value: str) -> bool:
    if len(value) != 44 or value[-1] != "=":
        return False
    return all(c in _KEY_CHARSET for c in value[:-1])


_INTERFACE_REQUIRED = {"PrivateKey", "Address"}
_INTERFACE_KNOWN_OPTIONAL = {"DNS", "MTU", "ListenPort", "Table", "FwMark", "SaveConfig"}
# Hook directives: wg-quick executes these via the shell when a config
# is brought up/down. Falak never executes them itself (not even in
# later milestones - connect uses wg-quick directly on the file path,
# unmodified), but a config containing them deserves an explicit
# warning: the file itself can run arbitrary commands if used with
# wg-quick, independent of anything Falak does.
_INTERFACE_HOOK_KEYS = {"PreUp", "PostUp", "PreDown", "PostDown"}
_PEER_REQUIRED = {"PublicKey", "AllowedIPs"}
_PEER_KNOWN_OPTIONAL = {"Endpoint", "PersistentKeepalive", "PresharedKey"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InterfaceConfig:
    """The validated ``[Interface]`` section of a WireGuard config."""

    private_key: str = field(repr=False)  # never included in repr/print
    address: tuple[str, ...]
    dns: tuple[str, ...] = ()
    mtu: int | None = None
    listen_port: int | None = None
    has_hook_directives: bool = False

    def __str__(self) -> str:  # defensive: block accidental str() leaks
        return "InterfaceConfig(private_key=[REDACTED], ...)"


@dataclass(frozen=True)
class PeerConfig:
    """A validated ``[Peer]`` section of a WireGuard config.

    ``public_key`` is retained and displayable: by design it is not
    secret (equivalent to an SSH public key). ``preshared_key`` *is*
    secret when present, so only its presence is exposed via
    ``has_preshared_key`` - the value itself is not stored on this
    object at all once validated, to minimize how long secret
    material stays reachable in memory.
    """

    public_key: str
    allowed_ips: tuple[str, ...]
    endpoint: str | None = None
    persistent_keepalive: int | None = None
    has_preshared_key: bool = False


@dataclass(frozen=True)
class WireGuardConfig:
    """A fully parsed and validated WireGuard configuration."""

    source_path: str
    interface: InterfaceConfig
    peers: tuple[PeerConfig, ...]
    warnings: tuple[str, ...] = ()

    def describe(self) -> str:
        """Human-readable summary safe to print or log.

        Never includes PrivateKey or PresharedKey values.
        """
        lines: list[str] = [f"Config file: {self.source_path}"]

        lines.append("Interface:")
        lines.append(f"  Address: {', '.join(self.interface.address)}")
        lines.append(f"  DNS: {', '.join(self.interface.dns) or '(not set)'}")
        lines.append(f"  MTU: {self.interface.mtu if self.interface.mtu else '(default)'}")
        lines.append(
            f"  ListenPort: {self.interface.listen_port if self.interface.listen_port is not None else '(default/random)'}"
        )
        lines.append("  PrivateKey: present, syntactically valid [REDACTED]")
        if self.interface.has_hook_directives:
            lines.append(
                "  Hook directives: PRESENT (PreUp/PostUp/PreDown/PostDown) - "
                "these run shell commands if this file is later used with "
                "wg-quick. Review them before connecting."
            )

        lines.append(f"Peers ({len(self.peers)}):")
        for i, peer in enumerate(self.peers, start=1):
            lines.append(f"  Peer {i}:")
            lines.append(f"    PublicKey: {peer.public_key}")
            lines.append(f"    AllowedIPs: {', '.join(peer.allowed_ips)}")
            lines.append(f"    Endpoint: {peer.endpoint or '(not set)'}")
            lines.append(
                f"    PersistentKeepalive: {peer.persistent_keepalive if peer.persistent_keepalive is not None else '(off)'}"
            )
            lines.append(
                f"    PresharedKey: {'present [REDACTED]' if peer.has_preshared_key else '(not set)'}"
            )

        if self.warnings:
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  - {w}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Low-level parsing
# ---------------------------------------------------------------------------


def _parse_sections(text: str) -> list[tuple[str, list[tuple[str, str, int]]]]:
    """Split raw config text into an ordered list of sections.

    Each section is ``(section_name, [(key, value, line_number), ...])``.
    Duplicate section names (e.g. multiple ``[Peer]`` blocks) are
    preserved as separate entries, matching how wg-quick itself reads
    multi-peer configs.

    Error messages reference only line numbers and key names - never
    raw line content - so a malformed secret-bearing line is never
    echoed back.
    """
    sections: list[tuple[str, list[tuple[str, str, int]]]] = []
    current_section: str | None = None
    current_items: list[tuple[str, str, int]] = []

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        # Strip comments. Per the official wg(8) CONFIGURATION FILE
        # FORMAT: "Characters after and including a '#' are considered
        # comments and are thus ignored." ';' has NO special meaning in
        # the real format - treating it as a comment delimiter (as an
        # earlier version of this parser did) would silently truncate
        # any line whose value legitimately contained a ';', which is
        # exactly the kind of silent data loss this parser must not do.
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            if current_section is not None:
                sections.append((current_section, current_items))
            current_section = line[1:-1].strip()
            current_items = []
            continue

        if current_section is None:
            raise ConfigValidationError(
                f"Line {line_no}: key-value pair found before any [Section] header."
            )

        if "=" not in line:
            raise ConfigValidationError(
                f"Line {line_no}: expected 'Key = Value' syntax."
            )

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            raise ConfigValidationError(f"Line {line_no}: empty key before '='.")
        if not value:
            raise ConfigValidationError(f"Line {line_no}: key '{key}' has no value.")

        current_items.append((key, value, line_no))

    if current_section is not None:
        sections.append((current_section, current_items))

    if not sections:
        raise ConfigValidationError(
            "File contains no [Interface] or [Peer] sections."
        )

    return sections


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _validate_key(value: str, *, field_name: str, line_no: int) -> str:
    if not _looks_like_wg_key(value):
        raise ConfigValidationError(
            f"Line {line_no}: '{field_name}' is not a syntactically valid "
            f"WireGuard key (expected 44 base64 characters ending in '=')."
        )
    return value


def _validate_address_list(value: str, *, line_no: int) -> tuple[str, ...]:
    entries = tuple(v.strip() for v in value.split(",") if v.strip())
    if not entries:
        raise ConfigValidationError(f"Line {line_no}: 'Address' has no entries.")
    for entry in entries:
        try:
            ipaddress.ip_interface(entry)
        except ValueError as exc:
            raise ConfigValidationError(
                f"Line {line_no}: 'Address' entry {entry!r} is not a valid "
                f"IPv4/IPv6 address or CIDR: {exc}"
            ) from exc
    return entries


def _validate_dns_list(value: str, *, line_no: int) -> tuple[str, ...]:
    entries = tuple(v.strip() for v in value.split(",") if v.strip())
    if not entries:
        raise ConfigValidationError(
            f"Line {line_no}: 'DNS' has no entries (value contains only "
            f"commas/whitespace)."
        )
    for entry in entries:
        try:
            ipaddress.ip_address(entry)
        except ValueError as exc:
            raise ConfigValidationError(
                f"Line {line_no}: 'DNS' entry {entry!r} is not a valid IP address: {exc}"
            ) from exc
    return entries


def _validate_allowed_ips(value: str, *, line_no: int) -> tuple[str, ...]:
    entries = tuple(v.strip() for v in value.split(",") if v.strip())
    if not entries:
        raise ConfigValidationError(f"Line {line_no}: 'AllowedIPs' has no entries.")
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ConfigValidationError(
                f"Line {line_no}: 'AllowedIPs' entry {entry!r} is not a valid "
                f"CIDR network: {exc}"
            ) from exc
    return entries


def _validate_port_range(
    value: str,
    *,
    field_name: str,
    line_no: int,
    min_value: int = 1,
    max_value: int = 65535,
) -> int:
    """Validate an integer field within [min_value, max_value].

    ``min_value`` defaults to 1 (an ordinary network port). ListenPort
    and PersistentKeepalive each pass ``min_value=0`` explicitly,
    because 0 is a documented, meaningful value for both - not a
    placeholder or an out-of-range input. See the dedicated wrappers
    below for the exact semantics of 0 in each case.
    """
    try:
        port = int(value)
    except ValueError as exc:
        raise ConfigValidationError(
            f"Line {line_no}: '{field_name}' must be an integer, got {value!r}."
        ) from exc
    if not (min_value <= port <= max_value):
        raise ConfigValidationError(
            f"Line {line_no}: '{field_name}' must be between {min_value} "
            f"and {max_value}, got {port}."
        )
    return port


def _validate_listen_port(value: str, *, line_no: int) -> int:
    """ListenPort: 0-65535.

    Per wg(8): "If listen-port is not specified, or set to 0, the port
    will be chosen randomly when the interface comes up." 0 is
    therefore a valid, meaningful value (explicit request for a random
    port) and must not be rejected.
    """
    return _validate_port_range(
        value, field_name="ListenPort", line_no=line_no, min_value=0
    )


def _validate_persistent_keepalive(value: str, *, line_no: int) -> int:
    """PersistentKeepalive: 0-65535.

    Per wg(8): "...between 1 and 65535 inclusive... If set to 0 ...,
    this option is disabled." 0 is therefore a valid, meaningful value
    (explicit keepalive-disabled) and must not be rejected. (The
    literal string "off", also accepted by wg(8) as a synonym for 0,
    is not currently supported by this parser - numeric 0 only.)
    """
    return _validate_port_range(
        value, field_name="PersistentKeepalive", line_no=line_no, min_value=0
    )


def _validate_mtu(value: str, *, line_no: int) -> int:
    try:
        mtu = int(value)
    except ValueError as exc:
        raise ConfigValidationError(
            f"Line {line_no}: 'MTU' must be an integer, got {value!r}."
        ) from exc
    if not (576 <= mtu <= 9000):
        raise ConfigValidationError(
            f"Line {line_no}: 'MTU' value {mtu} is outside the plausible "
            f"range 576-9000."
        )
    return mtu


def _validate_endpoint(value: str, *, line_no: int) -> str:
    # host:port, where an IPv6 host must be bracketed: [::1]:51820
    if value.startswith("["):
        if "]:" not in value:
            raise ConfigValidationError(
                f"Line {line_no}: 'Endpoint' looks like a bracketed IPv6 "
                f"address but is missing ']:<port>'."
            )
        host_part, _, port_part = value.rpartition(":")
        host = host_part.strip("[]")
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ConfigValidationError(
                f"Line {line_no}: 'Endpoint' host {host!r} is not a valid "
                f"IPv6 address: {exc}"
            ) from exc
    else:
        if ":" not in value:
            raise ConfigValidationError(
                f"Line {line_no}: 'Endpoint' must be in 'host:port' form."
            )
        host_part, _, port_part = value.rpartition(":")
        host = host_part
        if not host:
            raise ConfigValidationError(f"Line {line_no}: 'Endpoint' host is empty.")
        # Host may be an IPv4 literal or a hostname. We do not resolve
        # hostnames here (no network access in this module) - only a
        # basic character sanity check is performed for non-IP hosts.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not all(c.isalnum() or c in ".-" for c in host):
                raise ConfigValidationError(
                    f"Line {line_no}: 'Endpoint' host {host!r} contains "
                    f"characters not valid in a hostname."
                )

    try:
        port = int(port_part)
    except ValueError as exc:
        raise ConfigValidationError(
            f"Line {line_no}: 'Endpoint' port {port_part!r} is not an integer."
        ) from exc
    if not (1 <= port <= 65535):
        raise ConfigValidationError(
            f"Line {line_no}: 'Endpoint' port {port} must be between 1 and 65535."
        )

    return value


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_interface(
    items: list[tuple[str, str, int]], warnings: list[str]
) -> InterfaceConfig:
    seen_keys: dict[str, tuple[str, int]] = {}
    has_hooks = False

    for key, value, line_no in items:
        if key in seen_keys:
            raise ConfigValidationError(
                f"Line {line_no}: duplicate '{key}' in [Interface] "
                f"(first set at line {seen_keys[key][1]})."
            )
        seen_keys[key] = (value, line_no)

        if key in _INTERFACE_HOOK_KEYS:
            has_hooks = True
        elif key in _INTERFACE_REQUIRED or key in _INTERFACE_KNOWN_OPTIONAL:
            pass
        else:
            warnings.append(
                f"[Interface] line {line_no}: unrecognized key '{key}' - "
                f"ignored for validation purposes."
            )

    missing = _INTERFACE_REQUIRED - seen_keys.keys()
    if missing:
        raise ConfigValidationError(
            f"[Interface] is missing required key(s): {', '.join(sorted(missing))}."
        )

    priv_value, priv_line = seen_keys["PrivateKey"]
    private_key = _validate_key(priv_value, field_name="PrivateKey", line_no=priv_line)

    addr_value, addr_line = seen_keys["Address"]
    address = _validate_address_list(addr_value, line_no=addr_line)

    dns: tuple[str, ...] = ()
    if "DNS" in seen_keys:
        dns_value, dns_line = seen_keys["DNS"]
        dns = _validate_dns_list(dns_value, line_no=dns_line)

    mtu: int | None = None
    if "MTU" in seen_keys:
        mtu_value, mtu_line = seen_keys["MTU"]
        mtu = _validate_mtu(mtu_value, line_no=mtu_line)

    listen_port: int | None = None
    if "ListenPort" in seen_keys:
        lp_value, lp_line = seen_keys["ListenPort"]
        listen_port = _validate_listen_port(lp_value, line_no=lp_line)

    if has_hooks:
        warnings.append(
            "[Interface] contains hook directives (PreUp/PostUp/PreDown/"
            "PostDown). These will execute shell commands if this file is "
            "later used with wg-quick. Falak does not execute them itself "
            "but you should review them before connecting."
        )

    return InterfaceConfig(
        private_key=private_key,
        address=address,
        dns=dns,
        mtu=mtu,
        listen_port=listen_port,
        has_hook_directives=has_hooks,
    )


def _build_peer(items: list[tuple[str, str, int]], warnings: list[str]) -> PeerConfig:
    seen_keys: dict[str, tuple[str, int]] = {}

    for key, value, line_no in items:
        if key in seen_keys:
            raise ConfigValidationError(
                f"Line {line_no}: duplicate '{key}' in [Peer] "
                f"(first set at line {seen_keys[key][1]})."
            )
        seen_keys[key] = (value, line_no)
        if key not in _PEER_REQUIRED and key not in _PEER_KNOWN_OPTIONAL:
            warnings.append(
                f"[Peer] line {line_no}: unrecognized key '{key}' - ignored "
                f"for validation purposes."
            )

    missing = _PEER_REQUIRED - seen_keys.keys()
    if missing:
        raise ConfigValidationError(
            f"[Peer] is missing required key(s): {', '.join(sorted(missing))}."
        )

    pub_value, pub_line = seen_keys["PublicKey"]
    public_key = _validate_key(pub_value, field_name="PublicKey", line_no=pub_line)

    allowed_value, allowed_line = seen_keys["AllowedIPs"]
    allowed_ips = _validate_allowed_ips(allowed_value, line_no=allowed_line)

    endpoint: str | None = None
    if "Endpoint" in seen_keys:
        ep_value, ep_line = seen_keys["Endpoint"]
        endpoint = _validate_endpoint(ep_value, line_no=ep_line)

    keepalive: int | None = None
    if "PersistentKeepalive" in seen_keys:
        ka_value, ka_line = seen_keys["PersistentKeepalive"]
        keepalive = _validate_persistent_keepalive(ka_value, line_no=ka_line)

    has_psk = False
    if "PresharedKey" in seen_keys:
        psk_value, psk_line = seen_keys["PresharedKey"]
        _validate_key(psk_value, field_name="PresharedKey", line_no=psk_line)
        has_psk = True
        # The PresharedKey value is validated but deliberately not
        # retained on the PeerConfig object - only its presence is.

    return PeerConfig(
        public_key=public_key,
        allowed_ips=allowed_ips,
        endpoint=endpoint,
        persistent_keepalive=keepalive,
        has_preshared_key=has_psk,
    )


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def _check_permissions(path: str) -> list[str]:
    """Return advisory warnings about this file's permissions.

    This function only inspects permissions - it never changes them.
    Fixing an over-permissive config file is a decision for the user
    (or a later, explicit milestone), not something this read-only
    validator does on your behalf.
    """
    warnings: list[str] = []
    try:
        mode = os.stat(path).st_mode
    except OSError:
        # Caller already confirmed the file is readable before calling
        # this; a failure here is non-fatal for validation purposes.
        return warnings

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.append(
            f"File permissions for {path} are {stat.S_IMODE(mode):#o}, which "
            f"grant access to group and/or other users. This file contains "
            f"a WireGuard private key and should be mode 600 (owner "
            f"read/write only). Falak has NOT changed the permissions."
        )
    return warnings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: str) -> WireGuardConfig:
    """Load, parse, and validate a WireGuard configuration file.

    This function only reads the file at ``path``; it never writes to
    it, never changes its permissions, and never attempts a network
    or WireGuard operation. No elevated privileges are required beyond
    whatever is already needed to read the file as the current user.

    Raises:
        ConfigNotFoundError: ``path`` does not exist.
        ConfigPermissionError: ``path`` exists but cannot be read.
        ConfigValidationError: The file's contents are structurally
            or syntactically invalid.
    """
    if not os.path.exists(path):
        raise ConfigNotFoundError(f"Configuration file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except PermissionError as exc:
        raise ConfigPermissionError(
            f"Permission denied reading configuration file: {path}"
        ) from exc
    except OSError as exc:
        raise ConfigError(f"Could not read configuration file {path}: {exc}") from exc

    warnings: list[str] = _check_permissions(path)

    sections = _parse_sections(text)

    interface_items: list[tuple[str, str, int]] | None = None
    interface_line: int | None = None
    peer_item_groups: list[list[tuple[str, str, int]]] = []

    for name, items in sections:
        if name == "Interface":
            if interface_items is not None:
                first_line = interface_line if interface_line is not None else 0
                raise ConfigValidationError(
                    f"Multiple [Interface] sections found (first at line "
                    f"{first_line}); only one is allowed."
                )
            interface_items = items
            interface_line = items[0][2] if items else 0
        elif name == "Peer":
            peer_item_groups.append(items)
        else:
            warnings.append(
                f"Unrecognized section '[{name}]' - ignored for validation purposes."
            )

    if interface_items is None:
        raise ConfigValidationError("File has no [Interface] section.")
    if not peer_item_groups:
        raise ConfigValidationError(
            "File has no [Peer] section. At least one peer is required for "
            "a usable client configuration."
        )

    interface = _build_interface(interface_items, warnings)
    peers = tuple(_build_peer(items, warnings) for items in peer_item_groups)

    return WireGuardConfig(
        source_path=path,
        interface=interface,
        peers=peers,
        warnings=tuple(warnings),
    )


def ensure_safe_for_connection(
    config: WireGuardConfig, *, acknowledge_hooks: bool = False
) -> None:
    """Fail-closed gate for the future connection stage (Phase 2.5).

    This function establishes no connection and performs no
    networking of any kind - it only decides, given an already-parsed
    ``WireGuardConfig``, whether a later milestone is permitted to
    proceed to invoke ``wg-quick`` with it. It exists now, in the
    read-only validation milestone, so that milestone 2.5 has a
    concrete, already-reviewed gate to call rather than needing to
    invent hook-directive handling at connect time under time
    pressure.

    The design is fail-closed: if the config contains PreUp/PostUp/
    PreDown/PostDown hook directives (``config.interface.has_hook_directives``),
    this raises unless the caller explicitly passes
    ``acknowledge_hooks=True``. There is no default that silently
    permits connecting with unreviewed hooks - the safe outcome
    (reject) is what happens when the caller does nothing extra.

    ``acknowledge_hooks=True`` is intentionally not something this
    module decides on its own (e.g. by reading an environment variable
    or a config flag): Phase 2.5 must set it only after the user has
    actually been shown the hook commands and has explicitly agreed to
    run them - that interactive confirmation is out of scope for this
    read-only module and must not be assumed here.

    Raises:
        ConfigUnsafeForConnectionError: ``config`` contains hook
            directives and ``acknowledge_hooks`` is False.
    """
    if config.interface.has_hook_directives and not acknowledge_hooks:
        raise ConfigUnsafeForConnectionError(
            f"Configuration '{config.source_path}' contains hook directives "
            f"(PreUp/PostUp/PreDown/PostDown). wg-quick executes these as "
            f"shell commands when the interface is brought up or down. "
            f"Falak will not connect using this file until the hook "
            f"commands have been reviewed and explicitly acknowledged."
        )hi
