"""Target input validation and host-level Nmap evidence helpers."""

import ipaddress
import re
import shlex


def validate_target(value):
    """Accept one IP address, CIDR network, or DNS hostname; reject option/shell-like input."""
    target = (value or "").strip()
    if not target or target != value or any(ch.isspace() or ord(ch) < 32 for ch in target):
        raise ValueError("Target must be a single IP, CIDR network, or hostname without whitespace.")
    if target.startswith("-") or "://" in target or any(ch in target for ch in ";|&`$<>\\\\"):
        raise ValueError("Target contains unsupported characters.")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    hostname = target[:-1] if target.endswith(".") else target
    if len(hostname) > 253 or not hostname:
        raise ValueError("Hostname length is invalid.")
    labels = hostname.split(".")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not all(label_re.fullmatch(label) for label in labels):
        raise ValueError("Target is not a valid IP, CIDR network, or DNS hostname.")
    return target

def validate_ports(value):
    """Validate a comma-separated list of TCP port numbers/ranges."""
    ports = (value or "").strip()
    if not ports or ports != value:
        raise ValueError("Ports cannot be empty or contain surrounding whitespace.")
    for item in ports.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", item):
            raise ValueError(f"Invalid port expression: {item!r}")
        parts = [int(part) for part in item.split("-")]
        if any(port < 1 or port > 65535 for port in parts):
            raise ValueError(f"Port numbers must be between 1 and 65535: {item!r}")
        if len(parts) == 2 and parts[0] > parts[1]:
            raise ValueError(f"Port range start exceeds end: {item!r}")
    return ports

def normalize_nmap_args(value):
    """Parse and safely re-quote user-supplied Nmap arguments for python-nmap's shell command."""
    try:
        tokens = shlex.split(value or "")
    except ValueError as exc:
        raise ValueError(f"Invalid --nmap-args quoting: {exc}") from exc
    if not tokens:
        raise ValueError("--nmap-args cannot be empty.")
    if any(any(ord(ch) < 32 for ch in token) for token in tokens):
        raise ValueError("--nmap-args cannot contain control characters.")
    return shlex.join(tokens)

def build_host_os_fingerprint(os_matches, requested=False, minimum_accuracy=90):
    """Preserve raw Nmap OS evidence while only accepting high-confidence family labels."""
    if not isinstance(os_matches, (list, tuple)) or not os_matches:
        return {
            "status": "no_match" if requested else "not_requested",
            "platform_family": None,
            "nmap_name": None,
            "accuracy": None,
            "minimum_accuracy": minimum_accuracy,
            "source": "Nmap OS detection",
        }
    match = os_matches[0] if isinstance(os_matches[0], dict) else {}
    try:
        accuracy = int(match.get("accuracy"))
    except (TypeError, ValueError):
        accuracy = None
    if accuracy is not None and not 0 <= accuracy <= 100:
        accuracy = None
    platform = infer_target_platform(os_matches, minimum_accuracy=minimum_accuracy)
    return {
        "status": "accepted_high_confidence" if platform else "unconfirmed_low_confidence_or_unknown_family",
        "platform_family": platform,
        "nmap_name": str(match.get("name") or "")[:200] or None,
        "accuracy": accuracy,
        "minimum_accuracy": minimum_accuracy,
        "source": "Nmap OS detection",
    }

def infer_target_platform(os_matches, minimum_accuracy=90):
    """Infer a broad OS family only from a high-confidence Nmap OS match."""
    if not isinstance(os_matches, (list, tuple)) or not os_matches:
        return None
    match = os_matches[0] if isinstance(os_matches[0], dict) else {}
    try:
        accuracy = int(match.get("accuracy"))
    except (TypeError, ValueError):
        return None
    if not 0 <= accuracy <= 100 or accuracy < minimum_accuracy:
        return None
    os_name = str(match.get("name") or "").lower()
    if any(token in os_name for token in ("windows", "microsoft")):
        return "windows"
    if "linux" in os_name:
        return "linux"
    if any(token in os_name for token in ("freebsd", "openbsd", "netbsd", "solaris", "unix")):
        return "unix"
    if any(token in os_name for token in ("mac os", "macos", "darwin")):
        return "macos"
    return None

def scanned_hosts(scanner):
    """Return Nmap's resolved host list (which may contain IPs instead of the input hostname)."""
    hosts = list(scanner.all_hosts())
    if not hosts:
        raise RuntimeError("Nmap did not return any hosts. Check target reachability and scan options.")
    return hosts
