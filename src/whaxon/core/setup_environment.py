"""Host and package-manager detection for the first-run setup planner.

Detection is read-only: it never refreshes package indexes, invokes a manager,
contacts the network, or requests elevation. Manager presence is not proof that
a package mapping is safe or supported.
"""
from __future__ import annotations

import platform
import shutil
from typing import Any

_MANAGER_CANDIDATES = {
    "Linux": (
        ("apt", ("apt-get", "apt")),
        ("dnf", ("dnf",)),
        ("yum", ("yum",)),
        ("pacman", ("pacman",)),
        ("zypper", ("zypper",)),
        ("apk", ("apk",)),
    ),
    "Darwin": (("brew", ("brew",)),),
    "Windows": (
        ("winget", ("winget",)),
        ("choco", ("choco",)),
        ("scoop", ("scoop",)),
    ),
}


def detect_setup_environment(
    *, system: str | None = None, machine: str | None = None,
    release: str | None = None, distribution_id: str | None = None,
    which=shutil.which,
) -> dict[str, Any]:
    """Return host facts and available known package managers without side effects."""
    os_name = system or platform.system()
    architecture = machine or platform.machine()
    candidates = _MANAGER_CANDIDATES.get(os_name, ())
    managers: list[dict[str, str]] = []
    for manager_id, binaries in candidates:
        resolved = next((path for binary in binaries if (path := which(binary))), None)
        if resolved:
            managers.append({"id": manager_id, "executable": resolved})

    os_release = release if release is not None else platform.release()
    detected_distribution = (distribution_id or "").strip().lower()
    if os_name == "Linux" and distribution_id is None:
        try:
            detected_distribution = str(platform.freedesktop_os_release().get("ID", "")).lower()
        except (AttributeError, OSError):
            # Missing os-release data is an unsupported package-install host,
            # not a reason to guess a distro from its kernel release.
            detected_distribution = ""

    normalized_arch = architecture.lower()
    supported_arch = normalized_arch in {"x86_64", "amd64", "aarch64", "arm64"}
    installable_managers: list[str] = []
    if os_name == "Linux":
        if (
            supported_arch
            and detected_distribution in {"debian", "ubuntu", "kali"}
            and any(item["id"] == "apt" for item in managers)
        ):
            installable_managers.append("apt")
        support = "linux-curated-installer-available" if installable_managers else "linux-manual"
    elif os_name == "Darwin":
        if supported_arch and any(item["id"] == "brew" for item in managers):
            installable_managers.append("brew")
        support = "macos-curated-installer-available" if installable_managers else "macos-manual"
    elif os_name == "Windows":
        # Package-manager presence is diagnostic only: no native Windows
        # package IDs have passed the curated installer acceptance gate.
        support = "windows-manual"
    else:
        support = "unsupported"

    return {
        "system": os_name,
        "release": os_release,
        "distribution_id": detected_distribution,
        "architecture": architecture,
        "package_managers": managers,
        "support_status": support,
        "supported_installers": installable_managers,
        "unsupported_detected_managers": [
            item["id"] for item in managers if item["id"] not in installable_managers
        ],
        "wsl": bool(os_name == "Linux" and "microsoft" in (release if release is not None else platform.release()).lower()),
        "safety": {
            "read_only": True,
            "commands_executed": False,
            "network_accessed": False,
            "privilege_escalation_attempted": False,
        },
    }
