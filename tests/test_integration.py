import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from conftest import FIXTURES
from sc_agent.cli import scan


pytestmark = pytest.mark.integration
IMAGE = "alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"


@pytest.fixture(autouse=True)
def installed_scanners(monkeypatch):
    tools = Path(__file__).parents[1] / ".tools/bin"
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ.get("PATH", ""))
    if not shutil.which("trivy") or not shutil.which("zizmor"):
        pytest.skip("Execute python scripts/install_scanners.py antes dos testes de integração.")


def hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_real_repo_sboms_and_applicable_verified_patches(args, tmp_path):
    before = hashes(args.repo)
    args.sbom = [FIXTURES / "cyclonedx.json", FIXTURES / "spdx.json"]
    code, report = scan(args)
    assert code == 0, report["targets"]
    assert all(t["status"] == "complete" for t in report["targets"])
    assert {f["category"] for f in report["findings"]} == {"secret", "vulnerability", "misconfiguration", "pipeline"}
    assert {f["package"] for f in report["findings"]} >= {"requests", "minimist", "jinja2"}
    assert {p["path"] for p in report["patches"]} == {"requirements.txt", ".github/workflows/unsafe.yml"}
    assert hashes(args.repo) == before
    token = (args.repo / "config.env").read_text().split("GH_TOKEN=")[1].strip()
    assert all(token not in p.read_text() for p in args.out.rglob("*") if p.is_file())
    reviewed = tmp_path / "reviewed"
    shutil.copytree(args.repo, reviewed)
    for patch in report["patches"]:
        subprocess.run(["git", "apply", "--check", str(args.out / patch["file"])], cwd=reviewed, check=True)
        subprocess.run(["git", "apply", str(args.out / patch["file"])], cwd=reviewed, check=True)
    args.repo, args.out, args.sbom = reviewed, tmp_path / "review-report", []
    second_code, second = scan(args)
    assert second_code == 0
    resolved_ids = {identifier for patch in report["patches"] for identifier in patch["finding_ids"]}
    resolved_rules = {(f["rule"], f["package"]) for f in report["findings"] if f["id"] in resolved_ids}
    assert not resolved_rules & {(f["rule"], f["package"]) for f in second["findings"]}


def test_real_image_configuration_and_package_inventory(args):
    args.repo, args.image = None, [IMAGE]
    code, report = scan(args)
    assert code == 0, report["targets"]
    assert report["targets"][0]["packages_scanned"] >= 10
    assert report["targets"][0]["image_id"].startswith("sha256:")
    assert any(f["category"] == "misconfiguration" for f in report["findings"])


def test_real_safe_workflow_and_invalid_workflow(args):
    workflow = args.repo / ".github/workflows/unsafe.yml"
    shutil.copyfile(FIXTURES / "safe.yml", workflow)
    code, report = scan(args)
    assert code == 0
    assert not {"template-injection", "unpinned-uses", "excessive-permissions"} & {f["rule"] for f in report["findings"]}
    workflow.write_text("jobs: [invalid yaml")
    args.out = args.out.parent / "invalid-report"
    code, report = scan(args)
    assert code == 2
    assert any("zizmor" in note for note in report["targets"][0]["notes"])
