import copy
from pathlib import Path
import shutil
import subprocess

import pytest

from conftest import recording
from sc_agent.cli import scan
from sc_agent.patches import propose_patches
from sc_agent.scanners import ScanError, normalize_trivy, normalize_zizmor


def corrected_requirements():
    return {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt", "Type": "pip",
            "Packages": [{"Name": "requests", "Version": "2.33.0"}], "Vulnerabilities": []}]}


def test_requirements_patch_applies_and_preserves_original(args, scanners, tmp_path):
    scanners.after_requirements = corrected_requirements()
    original = (args.repo / "requirements.txt").read_bytes()
    code, report = scan(args, scanners)
    assert code == 0
    assert len(report["patches"]) == 1
    patch = args.out / report["patches"][0]["file"]
    assert "+requests==2.33.0" in patch.read_text()
    review = tmp_path / "review"
    shutil.copytree(args.repo, review)
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=review, check=True)
    subprocess.run(["git", "apply", str(patch)], cwd=review, check=True)
    assert (review / "requirements.txt").read_text() == "requests==2.33.0\n"
    assert (args.repo / "requirements.txt").read_bytes() == original
    assert len(report["patches"][0]["finding_ids"]) == 3


def test_workflow_safe_patch_applies(args, scanners, tmp_path):
    path = ".github/workflows/unsafe.yml"
    before = (args.repo / path).read_text()
    after = before.replace(" }} extra-text", " }}")
    scanners.patch_workflow = (path, after)
    scanners.after_zizmor = [f for f in recording("zizmor") if f["ident"] != "unsound-condition"]
    _, report = scan(args, scanners)
    assert len(report["patches"]) == 1
    patch = args.out / report["patches"][0]["file"]
    review = tmp_path / "review"
    shutil.copytree(args.repo, review)
    subprocess.run(["git", "apply", str(patch)], cwd=review, check=True)
    assert (review / path).read_text() == after
    assert (args.repo / path).read_text() == before


@pytest.mark.parametrize("content", ["requests>=2.31.0\n", "requests==2.31.0 --hash=sha256:123\n", "requests[socks]==2.31.0\n", "requests==2.31.0; python_version > '3.10'\n", "-r other.txt\n", "requests==2.31.0\nrequests==2.31.0\n"])
def test_complex_requirements_do_not_generate_patches(repo, scanners, tmp_path, content):
    (repo / "requirements.txt").write_text(content)
    findings, secrets, sensitive = normalize_trivy(recording("repository"), str(repo), repo)
    scanners.after_requirements = corrected_requirements()
    patches, _ = propose_patches(repo, str(repo), findings, sensitive, secrets, scanners, tmp_path)
    assert not patches
    assert not any(call[0] == "fs" for call in scanners.calls)


def test_patch_rejected_when_reanalysis_still_finds_vulnerability(args, scanners):
    scanners.after_requirements = recording("repository")
    _, report = scan(args, scanners)
    assert not report["patches"]
    assert any("descartado" in warning for warning in report["warnings"])


def test_patch_rejected_on_new_vulnerability(args, scanners):
    response = corrected_requirements()
    vulnerability = copy.deepcopy(next(r for r in recording("repository")["Results"] if r.get("Type") == "pip")["Vulnerabilities"][0])
    vulnerability.update(VulnerabilityID="NEW-CVE", InstalledVersion="2.33.0")
    response["Results"][0]["Vulnerabilities"].append(vulnerability)
    scanners.after_requirements = response
    assert not scan(args, scanners)[1]["patches"]


def test_patch_validation_failure_is_warning_not_clean_patch(args, scanners):
    original = scanners.trivy
    def fail(kind, target, cwd):
        if Path(target).name == "candidate":
            raise ScanError("trivy: timeout")
        return original(kind, target, cwd)
    scanners.trivy = fail
    code, report = scan(args, scanners)
    assert code == 0 and not report["patches"]
    assert any("não validado" in warning for warning in report["warnings"])


def test_secret_in_diff_context_blocks_patch(repo, scanners, tmp_path):
    token = "synthetic-private-context"
    (repo / "requirements.txt").write_text(f"# {token}\nrequests==2.31.0\n")
    findings, _, _ = normalize_trivy(recording("repository"), str(repo), repo)
    scanners.after_requirements = corrected_requirements()
    patches, warnings = propose_patches(repo, str(repo), findings, set(), {token}, scanners, tmp_path)
    assert not patches and any("segredo" in w for w in warnings)


def test_ambiguous_fix_never_guesses(repo, scanners, tmp_path):
    findings, secrets, sensitive = normalize_trivy(recording("repository"), str(repo), repo)
    next(f for f in findings if f.package == "requests").fixed_versions = ["2.32.0", "3.0.0"]
    scanners.after_requirements = corrected_requirements()
    patches, _ = propose_patches(repo, str(repo), findings, sensitive, secrets, scanners, tmp_path)
    assert not patches
