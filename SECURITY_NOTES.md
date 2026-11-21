# Falak — Known Security Limitations (for future hardening)

This file is a running log of security-relevant limitations identified
during development. It does not change behavior — it is a record for
future milestones to address deliberately, not silently. Entries are
grouped by the milestone that introduced them.

## Milestone 2.1 — subprocess wrapper, logging, CLI skeleton

1. **Secret redaction is pattern-based, not a general secret scanner.**
   `redact_secrets()` (falak/utils/logger.py) matches WireGuard's
   specific key shape (43 base64 chars + `=`) and `PrivateKey=`/
   `PresharedKey=` lines. A secret in an unexpected format, or split
   across a line wrap, could slip through. Acceptable for now because
   no secret-bearing data flows through logging yet, but must be
   re-reviewed before 2.5 (connect), where `wg-quick` output could
   plausibly include config excerpts.

2. **No privilege-escalation handling yet.** `run_command()`
   (falak/utils/shell.py) does not add `sudo` or otherwise request
   elevation. This is deliberate — deferred to the milestone that
   actually needs to run `wg-quick`/`ip`/`nft` — but means there is no
   established pattern yet for *how* Falak will request privileges,
   and that design choice (e.g. `sudo` prompts vs. a privileged helper
   process) still needs a dedicated security review.

3. **`CommandResult` captures stdout/stderr with no size bound.** A
   pathological or malicious subprocess producing unbounded output
   could consume memory. Low risk for the trusted local tools Falak
   will call (`wg`, `ip`, `nft`), but worth a cap if Falak ever shells
   out to anything less trusted.

4. **Logging destination is stdout/stderr only.** No log file, no
   rotation, no path with controlled permissions. If persistent
   logging is added later, the log file needs the same 600-style
   permission discipline as the WireGuard config itself, since
   redaction is a mitigation, not a guarantee.

## Milestone 2.2 — WireGuard config parsing and validation

5. **Key validation is syntactic only, not cryptographic.**
   `_looks_like_wg_key()` (falak/config/loader.py) checks length and
   base64 charset — it does *not* decode the key and confirm it is a
   valid Curve25519 scalar, and does not confirm a public key
   corresponds to any private key. A string that merely has the right
   shape will pass validation here and only fail later, at `wg-quick`
   / kernel level, when an actual connection is attempted. This is an
   accepted scope limit for a read-only parser; flag it to the user if
   validate-only output is ever presented as a stronger guarantee than
   it is.

6. **File permission issues are reported, never corrected.**
   `_check_permissions()` warns on a world/group-readable config file
   but takes no corrective action (no automatic `chmod`). This was a
   deliberate choice (read-only milestone, no filesystem
   modification), but means a user who ignores the warning keeps an
   exposed private key on disk indefinitely. Worth revisiting whether
   `falak config --fix-permissions` (explicit, opt-in) should exist in
   a later milestone.

7. **Hook directives (`PreUp`/`PostUp`/`PreDown`/`PostDown`) are
   detected and warned about, but not otherwise restricted.** Falak
   itself never executes them, but if a `.conf` file is later passed
   to `wg-quick` (2.5+), `wg-quick` will execute whatever shell
   commands these directives contain, with whatever privileges
   `wg-quick` runs under. A config file from an untrusted source is
   therefore a code-execution vector *independent of anything Falak's
   Python code does*. This needs explicit, visible handling before
   2.5 — e.g. requiring interactive confirmation before connecting
   with a config that contains hook directives, not just a warning
   buried in `config` output.

8. **No file size cap on the config being parsed.** `load_config()`
   reads the entire file into memory with no limit. Low real-world
   risk for a local config file, but worth a sanity cap (e.g. reject
   anything over a few hundred KB) before this path can be reached
   with attacker-controlled input.

9. **Endpoint hostname validation is character-only, not
   resolution-based** (and deliberately so — this module does no
   network access). A syntactically plausible but non-existent or
   malicious hostname will pass validation here; DNS resolution issues
   would only surface at actual connect time in a later milestone.

10. **No policy on "unsafe" `AllowedIPs`/`Address` values.** e.g. a
    config routing `0.0.0.0/0` through a peer is accepted exactly like
    any other valid CIDR — correctly, since that's the normal
    full-tunnel case — but the loader does not flag unusual patterns
    (e.g. an `Address` that collides with common private LAN ranges,
    which could cause confusing routing later). Not a vulnerability by
    itself; worth considering as a diagnostics-stage warning in 2.7.

## Milestone 2.3 — Read-only environment detection

11. **DNS classification is heuristic, based on `/etc/resolv.conf`'s
    symlink target and `systemctl is-active`.** A system that manages
    DNS through some other mechanism entirely (e.g. a custom resolver
    stack, a container runtime overlay, or a non-systemd init) will
    correctly fall through to `DnsMethod.UNKNOWN` rather than being
    misclassified — this is the intended fail-safe behavior per your
    requirement, confirmed by `test_symlink_to_unrecognized_target_is_unknown`
    and `test_missing_resolv_conf_is_unknown_and_fails_safe`. The
    trade-off: some unusual-but-legitimate systemd-resolved or
    resolvconf setups whose symlink target doesn't match the
    patterns checked here (`"systemd"`/`"resolve"`,
    `"resolvconf"`, `"networkmanager"`) will also report UNKNOWN
    rather than being recognized, which is the safe direction to err
    in but may need broadening later based on real Kali testing.

12. **`nmcli device status` output could reveal connection/profile
    names** (e.g. a saved Wi-Fi SSID used as a connection name) in the
    `active_interfaces`/detail fields of the report. These are not
    credentials or secrets, but they are a form of environment
    metadata; worth keeping in mind if `falak status` output is ever
    shared/pasted publicly (e.g. in a bug report).

13. **Version-probe commands (`wg --version`, `ip -V`, `nft --version`)
    are run with no special sandboxing beyond the existing
    `run_command()` timeout/argument-list protections.** This is the
    same trust model as every other use of `falak.utils.shell` — these
    are standard system binaries resolved via `PATH`, not
    user-supplied paths, so this is consistent with 2.1's existing
    scope, not a new risk class.

14. **This module performs zero WireGuard config/key handling** — by
    design, `falak.core.environment` has no dependency on
    `falak.config.loader` at all. This is a structural guarantee
    rather than a redaction-based one: there is no code path here that
    could leak key material, because no key material ever enters this
    module.

## Correction round — Phase 2.2 review (pre-2.4)

Four issues identified in review of the existing 2.2 implementation were
corrected in `falak/config/loader.py`. None of these are new features;
all are fixes to match documented WireGuard semantics (`wg(8)`) that
the original implementation got wrong:

- **Comment parsing.** The parser was treating both `#` and `;` as
  comment delimiters. Verified against the official `wg(8)` man page:
  only `#` is a comment character in the real WireGuard config format.
  Treating `;` as one risked silently truncating a line whose value
  legitimately contained a `;`. Fixed to only strip `#`; a line that
  looks like a `;`-prefixed "comment" is now correctly rejected as
  invalid syntax rather than silently ignored.
- **`ListenPort` / `PersistentKeepalive` zero values.** Both were
  restricted to 1-65535. Per `wg(8)`, `ListenPort = 0` means "choose a
  port randomly" and `PersistentKeepalive = 0` means "explicitly
  disabled" — both documented, meaningful values, not errors. Split
  into dedicated validators (`_validate_listen_port`,
  `_validate_persistent_keepalive`, both 0-65535) built on a shared
  `_validate_port_range` helper. Display logic in `describe()` was
  also fixed, since it used Python truthiness (`if x else ...`), which
  would have rendered an explicit `0` identically to "not set."
- **DNS empty-entries.** `DNS = ,,,` (non-empty raw value, zero real
  entries after splitting) was silently accepted as an empty DNS list.
  Now rejected with `ConfigValidationError`.
- **Hook-directive fail-closed gate.** Item 7 in the original
  limitations list (above) flagged that hook directives were detected
  and warned about but had no enforcement mechanism. Added
  `ensure_safe_for_connection()` and `ConfigUnsafeForConnectionError`:
  a ready-made, fail-closed gate for Phase 2.5 to call before ever
  invoking `wg-quick` — raises by default on unacknowledged hooks, and
  the default is "reject," not "allow." This module still does not
  call it itself and still performs no networking; it only prepares
  the gate.

16 new targeted tests added (`tests/test_config_loader.py`); full
suite re-run, 99/99 passing. No change to `falak/core/environment.py`,
`falak/cli.py`, or any Phase 2.1 file in this round.

---

Nothing above requires action to proceed to 2.4. These are tracked
risks, not open vulnerabilities in anything currently connected to
real traffic — Falak still performs no networking, routing, DNS, or
firewall *modification* as of the end of 2.3 (2.3 adds read-only
inspection only).
