"""E5 Docker packaging is opt-in and preserves the separate lab compose."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_e5_compose_has_separate_durable_worker_and_shared_state():
    content = (ROOT / "docker-compose.e5.yml").read_text(encoding="utf-8")
    assert "  web:" in content
    assert "  workflow-worker:" in content
    assert content.count("      - e5-state:/data") == 2
    assert content.count("      WHAXON_DATA: /data") == 2
    assert "      - serve-requests" in content
    assert "      - --max-runs-per-batch" in content
    assert '"127.0.0.1:5001:5001"' in content
    assert content.count("    read_only: true") == 2
    assert content.count("      - ALL") == 2
    assert content.count("      - no-new-privileges:true") == 2
    assert "WHAXON_AUTH_PASS: ${WHAXON_AUTH_PASS:?" in content
    assert "WHAXON_AUTH_USER: ${WHAXON_AUTH_USER:?" in content
    assert "      - e5-state:/data" in content


def test_e5_compose_disables_web_local_drain_not_external_worker():
    content = (ROOT / "docker-compose.e5.yml").read_text(encoding="utf-8")
    web, worker = content.split("  workflow-worker:", 1)
    assert 'WHAXON_V2_EXTERNAL_WORKER: "1"' in web
    assert "WHAXON_V2_EXTERNAL_WORKER:" not in worker


def test_e5_compose_does_not_replace_target_lab_configuration():
    laboratory = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    production = (ROOT / "docker-compose.e5.yml").read_text(encoding="utf-8")
    assert "msf-target:" in laboratory
    assert "msf-target:" not in production
    assert "whaxon-lab" not in production
    assert "ipv4_address:" not in production
    assert "NET_ADMIN" not in production


def test_e5_container_image_avoids_baking_operator_proof_data_and_prepares_volume():
    image = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "COPY data/" not in image
    assert "mkdir -p /data" in image
    assert "chown -R whaxon:whaxon /app /data" in image
    assert "USER whaxon" in image
    assert "data/" in ignore.splitlines()
    assert ".git" in ignore.splitlines()


def test_e5_image_prepares_separate_nonroot_offline_backup_mount():
    image = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "mkdir -p /data /e5-backups" in image
    assert "chown -R whaxon:whaxon /app /data /e5-backups" in image


def test_e5_container_build_contains_all_hatch_forced_systemd_resources():
    image = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "COPY whaxon.service whaxon-workflow-worker.service ./" in image
    assert '"whaxon.service" = "whaxon/data/systemd/whaxon.service"' in metadata
    assert ('"whaxon-workflow-worker.service" = '
            '"whaxon/data/systemd/whaxon-workflow-worker.service"') in metadata
