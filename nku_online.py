#!/usr/bin/env python3
"""Keep a headless NKU device reachable through Tailscale.

A healthy network is one where at least one currently-online Tailscale peer
answers ``tailscale ping``.  Recovery is intentionally progressive: restart
Tailscale, cycle and reconnect Wi-Fi, try alternate Wi-Fi profiles, and
rotate the campus profile MAC.  NKU_WLAN portal authentication is attempted
only after that profile is connected but peer connectivity still fails.
"""

import argparse
import concurrent.futures
import fcntl
import json
import logging
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

LOGGER = logging.getLogger("nku-online")
INTERFACE = os.environ.get("WIFI_INTERFACE", "wlan0")
PROFILES = tuple(
    name.strip()
    for name in os.environ.get("WIFI_PROFILES", "Xiaomi_NKU,NKU_WLAN").split(",")
    if name.strip()
)
PREFERRED_PROFILE = os.environ.get("PREFERRED_WIFI", "Xiaomi_NKU")
AUTH_PROFILE = os.environ.get("NKU_AUTH_WIFI", "NKU_WLAN")
PROBE_TIMEOUT = float(os.environ.get("TAILSCALE_PROBE_TIMEOUT", "3"))
CONFIRM_DELAY = float(os.environ.get("FAILURE_CONFIRM_DELAY", "10"))
WIFI_SETTLE_DELAY = float(os.environ.get("WIFI_SETTLE_DELAY", "12"))
AUTH_TIMEOUT = float(os.environ.get("NKU_AUTH_TIMEOUT", "75"))
LOCK_PATH = Path("/run/nku-online.lock")


def run_command(argv, timeout=30):
    """Run a bounded command and return CompletedProcess, or None on failure."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOGGER.warning("command failed: %s: %s", argv[0], exc)
        return None
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        LOGGER.warning(
            "command exited %d: %s%s",
            result.returncode,
            " ".join(argv),
            f": {detail}" if detail else "",
        )
    return result


def tailscale_targets():
    """Return unique (display name, address) pairs for online tailnet peers."""
    result = run_command(["tailscale", "status", "--json"], timeout=10)
    if result is None or result.returncode != 0:
        return []
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        LOGGER.warning("could not parse tailscale status: %s", exc)
        return []

    if not isinstance(status, dict):
        LOGGER.warning("tailscale status returned an unexpected JSON value")
        return []
    peers = status.get("Peer")
    if isinstance(peers, dict):
        entries = peers.values()
    elif isinstance(peers, list):
        entries = peers
    else:
        entries = ()
    targets = []
    seen = set()
    for peer in entries:
        if not isinstance(peer, dict) or not peer.get("Online"):
            continue
        addresses = peer.get("TailscaleIPs") or []
        if not addresses:
            continue
        address = addresses[0]
        if address in seen:
            continue
        seen.add(address)
        name = peer.get("HostName") or peer.get("DNSName") or address
        targets.append((name.rstrip("."), address))

    for address in os.environ.get("TAILSCALE_TARGETS", "").split(","):
        address = address.strip()
        if address and address not in seen:
            seen.add(address)
            targets.append((address, address))
    return targets


def ping_peer(peer):
    name, address = peer
    result = run_command(
        [
            "tailscale",
            "ping",
            "--until-direct=false",
            f"--timeout={PROBE_TIMEOUT:g}s",
            "--c=1",
            address,
        ],
        timeout=PROBE_TIMEOUT + 3,
    )
    return name, result is not None and result.returncode == 0


def probe_once():
    """Return True when any online Tailscale peer answers."""
    targets = tailscale_targets()
    if not targets:
        LOGGER.warning("no online Tailscale peers available to probe")
        return False

    reachable = []
    workers = min(len(targets), 16)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for name, succeeded in pool.map(ping_peer, targets):
            if succeeded:
                reachable.append(name)
    if reachable:
        LOGGER.info("Tailscale peer reachable: %s", ", ".join(reachable))
        return True
    LOGGER.warning("all %d Tailscale peer probes failed", len(targets))
    return False


def confirmed_offline():
    if probe_once():
        return False
    LOGGER.warning("initial probe failed; confirming in %.0f seconds", CONFIRM_DELAY)
    time.sleep(CONFIRM_DELAY)
    return not probe_once()


def active_profile():
    result = run_command(
        ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", INTERFACE],
        timeout=10,
    )
    if result is None or result.returncode != 0:
        return None
    profile = result.stdout.strip()
    return profile if profile and profile != "--" else None


def profile_exists(profile):
    result = run_command(
        ["nmcli", "-g", "connection.id", "connection", "show", profile],
        timeout=10,
    )
    return result is not None and result.returncode == 0


def random_mac():
    octets = bytearray(secrets.token_bytes(6))
    octets[0] = (octets[0] & 0xFC) | 0x02
    return ":".join(f"{octet:02x}" for octet in octets)


def connect_profile(profile, *, cycle_radio=False, rotate_mac=False):
    """Activate one NetworkManager profile, optionally cycling radio/MAC."""
    if not profile_exists(profile):
        LOGGER.warning("Wi-Fi profile does not exist: %s", profile)
        return False

    if rotate_mac:
        mac = random_mac()
        LOGGER.warning("rotating %s cloned MAC to %s", profile, mac)
        result = run_command(
            [
                "nmcli",
                "connection",
                "modify",
                profile,
                "802-11-wireless.cloned-mac-address",
                mac,
            ],
            timeout=15,
        )
        if result is None or result.returncode != 0:
            return False

    if cycle_radio:
        LOGGER.warning("cycling Wi-Fi radio")
        run_command(["nmcli", "radio", "wifi", "off"], timeout=10)
        time.sleep(3)
        result = run_command(["nmcli", "radio", "wifi", "on"], timeout=10)
        if result is None or result.returncode != 0:
            return False
        time.sleep(3)

    LOGGER.warning("activating Wi-Fi profile %s on %s", profile, INTERFACE)
    result = run_command(
        ["nmcli", "connection", "up", "id", profile, "ifname", INTERFACE],
        timeout=60,
    )
    if result is None or result.returncode != 0:
        return False
    time.sleep(WIFI_SETTLE_DELAY)
    return True


def authenticate_nku():
    username = os.environ.get("NKU_USERNAME")
    password = os.environ.get("NKU_PASSWORD")
    if not username or not password:
        LOGGER.warning("NKU_USERNAME/NKU_PASSWORD not configured; skipping portal login")
        return False

    LOGGER.warning(
        "attempting NKU_WLAN portal authentication (timeout %.0fs)", AUTH_TIMEOUT
    )
    script_dir = Path(__file__).resolve().parent
    command = (
        "import os, sys; import login; "
        "sys.exit(login.login(os.environ['NKU_USERNAME'], "
        "os.environ['NKU_PASSWORD']))"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", command],
            cwd=script_dir,
            capture_output=True,
            text=True,
            timeout=AUTH_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        LOGGER.warning("portal authentication did not complete: %s", exc)
        return False
    output = (result.stdout or result.stderr).strip()
    if output:
        LOGGER.info("portal authentication: %s", output.replace("\n", " | "))
    if result.returncode != 0:
        LOGGER.warning("portal authentication exited %d", result.returncode)
        return False
    return True


def verify_profile(profile):
    """Probe connectivity, authenticating NKU_WLAN once when necessary."""
    if probe_once():
        return True
    if profile == AUTH_PROFILE:
        authenticate_nku()
        time.sleep(3)
        return probe_once()
    return False


def recovery_profiles(current):
    ordered = []
    if current in PROFILES:
        ordered.append(current)
    for profile in PROFILES:
        if profile not in ordered:
            ordered.append(profile)
    return ordered


def recover(force_all=False):
    """Run progressive recovery. force_all exercises every stage for testing."""
    any_success = False

    LOGGER.warning("restarting tailscaled")
    run_command(["systemctl", "restart", "tailscaled.service"], timeout=30)
    time.sleep(5)
    online = probe_once()
    any_success |= online
    if online and not force_all:
        return True

    current = active_profile()
    profiles = recovery_profiles(current)
    if not profiles:
        LOGGER.error("no configured Wi-Fi profiles")
        return any_success

    first = profiles[0]
    if connect_profile(first, cycle_radio=True):
        online = verify_profile(first)
        any_success |= online
        if online and not force_all:
            return True

    for profile in profiles:
        if profile != first and connect_profile(profile):
            online = verify_profile(profile)
            any_success |= online
            if online and not force_all:
                return True

        if profile == AUTH_PROFILE and connect_profile(profile, rotate_mac=True):
            online = verify_profile(profile)
            any_success |= online
            if online and not force_all:
                return True

    if active_profile() != PREFERRED_PROFILE:
        LOGGER.warning("restoring preferred Wi-Fi profile %s", PREFERRED_PROFILE)
        if connect_profile(PREFERRED_PROFILE):
            online = verify_profile(PREFERRED_PROFILE)
            any_success |= online

    return probe_once() if force_all else any_success


def acquire_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_file = LOCK_PATH.open("w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        return None
    return lock_file


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--probe", action="store_true", help="probe peers without changing system state"
    )
    mode.add_argument(
        "--force-recovery",
        action="store_true",
        help="exercise every recovery stage even if connectivity returns",
    )
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args()
    if args.probe:
        return 0 if probe_once() else 1
    if os.geteuid() != 0:
        LOGGER.error("recovery must run as root")
        return 2

    lock_file = acquire_lock()
    if lock_file is None:
        LOGGER.info("another recovery instance is already running")
        return 0
    try:
        if not args.force_recovery and not confirmed_offline():
            return 0
        LOGGER.warning("network considered offline; starting recovery")
        if recover(force_all=args.force_recovery):
            LOGGER.info("network recovery succeeded")
            return 0
        LOGGER.error("network remains offline after all recovery stages")
        return 1
    finally:
        lock_file.close()


if __name__ == "__main__":
    sys.exit(main())
