from __future__ import annotations

from whaxon.core.setup_environment import detect_setup_environment


def test_linux_detects_only_available_managers_without_running_them():
    calls = []
    def which(binary):
        calls.append(binary)
        return "/usr/bin/apt-get" if binary == "apt-get" else None

    result = detect_setup_environment(
        system="Linux", machine="x86_64", release="6.1", which=which
    )
    assert result["package_managers"] == [{"id": "apt", "executable": "/usr/bin/apt-get"}]
    assert result["support_status"] in {"linux-curated-installer-available", "linux-manual"}
    assert result["supported_installers"] in ([], ["apt"])
    assert result["safety"]["read_only"] is True
    assert calls == ["apt-get", "dnf", "yum", "pacman", "zypper", "apk"]


def test_macos_does_not_assume_homebrew_is_installed():
    result = detect_setup_environment(
        system="Darwin", machine="arm64", release="24.0", which=lambda _: None
    )
    assert result["package_managers"] == []
    assert result["support_status"] == "macos-manual"


def test_windows_detects_winget_without_invoking_it():
    result = detect_setup_environment(
        system="Windows", machine="AMD64", release="10",
        which=lambda name: "C:/Windows/winget.exe" if name == "winget" else None,
    )
    assert result["package_managers"] == [{"id": "winget", "executable": "C:/Windows/winget.exe"}]
    assert result["support_status"] == "windows-manual"
    assert result["supported_installers"] == []
    assert result["unsupported_detected_managers"] == ["winget"]


def test_unknown_platform_is_explicitly_unsupported():
    result = detect_setup_environment(
        system="FreeBSD", machine="amd64", release="14", which=lambda _: None
    )
    assert result["support_status"] == "unsupported"
    assert result["package_managers"] == []


def test_wsl_is_reported_from_kernel_release():
    result = detect_setup_environment(
        system="Linux", machine="x86_64", release="5.15.90-microsoft-standard-WSL2",
        which=lambda _: None,
    )
    assert result["wsl"] is True


def test_linux_installer_support_requires_curated_distribution_and_architecture():
    def apt(name):
        return "/usr/bin/apt-get" if name == "apt-get" else None
    debian = detect_setup_environment(
        system="Linux", machine="x86_64", release="6.1",
        distribution_id="debian", which=apt,
    )
    assert debian["supported_installers"] == ["apt"]
    assert debian["support_status"] == "linux-curated-installer-available"

    arch = detect_setup_environment(
        system="Linux", machine="x86_64", release="6.1",
        distribution_id="arch", which=apt,
    )
    assert arch["supported_installers"] == []
    assert arch["support_status"] == "linux-manual"

    unknown_arch = detect_setup_environment(
        system="Linux", machine="riscv64", release="6.1",
        distribution_id="debian", which=apt,
    )
    assert unknown_arch["supported_installers"] == []
    assert unknown_arch["support_status"] == "linux-manual"
