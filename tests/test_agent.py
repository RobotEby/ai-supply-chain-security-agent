import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from conftest import FIXTURES, recording
from sc_agent.cli import main, parser, scan
from sc_agent.inputs import package_inventory, read_sbom, repository_coverage, sbom_coverage, snapshot
from sc_agent.models import group_findings, redact
from sc_agent.reporting import markdown
from sc_agent.scanners import ScanError, normalize_trivy, normalize_zizmor


def test_real_recordings_cover_four_targets(repo):
    findings, _, sensitive = normalize_trivy(recording("repository"), str(repo), repo)
    assert {f.category for f in findings} == {"vulnerability", "misconfiguration", "secret"}
    assert {f.package for f in findings} >= {"requests", "jinja2", "minimist", "lodash", "urllib3"}
    assert sensitive == {"config.env"}
    assert not repository_coverage(repo, recording("repository"))
    pipelines = normalize_zizmor(recording("zizmor"), str(repo), repo)
    assert {f.rule for f in pipelines} >= {"excessive-permissions", "unpinned-uses", "template-injection"}
    for kind in ("cyclonedx", "spdx", "image"):
        scanned, _, _ = normalize_trivy(recording(kind), kind)
        assert scanned


def test_grouping_preserves_locations_severity_and_order(repo):
    findings, _, _ = normalize_trivy(recording("repository"), str(repo), repo)
    extra = copy.deepcopy(findings[0])
    extra.locations[0]["target"] = "other"
    grouped = group_findings([*findings, extra])
    assert len(grouped) == len(group_findings(findings))
    combined = next(f for f in grouped if f["id"] == extra.id)
    assert {loc["target"] for loc in combined["locations"]} == {str(repo), "other"}
    assert grouped[0]["severity"] == "CRITICAL"
    assert combined["original_severity"]


@pytest.mark.parametrize("policy,expected", [("none", 0), ("critical", 1), ("high", 1), ("low", 1)])
def test_policy_and_secret_redaction(args, scanners, policy, expected):
    args.fail_on = policy
    token = (args.repo / "config.env").read_text().split("GH_TOKEN=")[1].strip()
    code, report = scan(args, scanners)
    assert code == expected
    assert report["status"] == "complete"
    assert report["schema_version"] == 1
    assert any(f["category"] == "secret" for f in report["findings"])
    for path in args.out.rglob("*"):
        if path.is_file():
            assert token not in path.read_text()
    assert report["tools"]["trivy"]["VulnerabilityDB"]["UpdatedAt"]


def test_multiple_images_and_sboms(args, scanners):
    args.image = ["alpine:3.18", "alpine:3.18", "example:1"]
    args.sbom = [FIXTURES / "cyclonedx.json", FIXTURES / "spdx.json"]
    code, report = scan(args, scanners)
    assert code == 0
    assert len(report["targets"]) == 5
    assert all(t["status"] == "complete" for t in report["targets"])
    lodash = next(f for f in report["findings"] if f["package"] == "lodash")
    assert len(lodash["locations"]) == 3


@pytest.mark.parametrize("filename,content", [
    ("new/package.json", '{"dependencies":{"missing":"1.0.0"}}'),
    ("new/pyproject.toml", '[project]\ndependencies = ["missing==1.0"]'),
    ("requirements.txt", 'unresolved>=1.0\n'),
    ("new/package-lock.json", '{broken'),
    ("new/requirements.txt", 'notseen==1.0\n'),
])
def test_missing_or_invalid_coverage_is_failure(args, scanners, filename, content):
    path = args.repo / filename
    path.parent.mkdir(exist_ok=True)
    path.write_text(content)
    code, report = scan(args, scanners)
    assert code == 2
    assert report["status"] == "incomplete"
    assert report["targets"][0]["notes"]
    assert not report["patches"]


def test_scanner_failure_keeps_other_findings_and_beats_threshold(args, scanners):
    original = scanners.trivy
    def fail(kind, *positional):
        if kind == "fs":
            raise ScanError("trivy: falha de acesso à base")
        return original(kind, *positional)
    scanners.trivy = fail
    args.image = ["alpine:3.18"]
    args.fail_on = "high"
    code, report = scan(args, scanners)
    assert code == 2
    assert any(f["source"] == "zizmor" for f in report["findings"])
    assert report["targets"][1]["status"] == "complete"
    assert (args.out / "report.json").is_file()


@pytest.mark.parametrize("name,content", [("unknown.json", '{}'), ("bad.json", '{'), ("xml.json", '<bom/>')])
def test_invalid_sbom_reported(args, scanners, name, content, tmp_path):
    source = tmp_path / name
    source.write_text(content)
    args.repo = None
    args.sbom = [source]
    code, report = scan(args, scanners)
    assert code == 2
    assert report["targets"][0]["status"] == "incomplete"
    assert not scanners.calls


def test_partial_sbom_coverage(args, scanners, tmp_path):
    source = tmp_path / "partial.json"
    content = json.loads((FIXTURES / "cyclonedx.json").read_text())
    content["components"].append({"type": "library", "name": "unknown"})
    source.write_text(json.dumps(content))
    args.repo, args.sbom = None, [source]
    assert scan(args, scanners)[0] == 2


def test_source_and_existing_output_are_preserved(args, scanners):
    before = {p.relative_to(args.repo): p.read_bytes() for p in args.repo.rglob("*") if p.is_file()}
    scan(args, scanners)
    for path, data in before.items():
        assert (args.repo / path).read_bytes() == data
    saved = (args.out / "report.json").read_bytes()
    with pytest.raises(ScanError, match="vazio"):
        scan(args, scanners)
    assert (args.out / "report.json").read_bytes() == saved
    args.out = args.repo
    with pytest.raises(ScanError, match="ancestral"):
        scan(args, scanners)


def test_snapshot_excludes_symlinks_generated_output_and_dependencies(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("not allowed")
    (repo / "link").symlink_to(outside)
    (repo / "node_modules").mkdir()
    (repo / "node_modules/private").write_text("ignored")
    output = repo / "reports"
    output.mkdir()
    (output / "report.json").write_text("ignored")
    destination = tmp_path / "snapshot"
    notes = snapshot(repo, destination, output)
    assert notes and not (destination / "link").exists()
    assert not (destination / "node_modules").exists()
    assert not (destination / "reports").exists()
    assert (destination / "requirements.txt").is_file()


@pytest.mark.parametrize("reference", ["--help", "$(touch pwned)", "bad\nref", "https://u:password@example.com/image", "name@invalid", "user:secret@host/name"])
def test_untrusted_image_argument_never_reaches_scanner(args, scanners, reference):
    args.repo, args.image = None, [reference]
    code, report = scan(args, scanners)
    assert code == 2 and not scanners.calls
    assert report["targets"][0]["input"] == "[referência inválida]"


def test_cli_requires_target_and_output():
    with pytest.raises(SystemExit) as error:
        main(["scan", "--out", "/tmp/unused"])
    assert error.value.code == 2
    with pytest.raises(SystemExit):
        main(["scan", "--image", "alpine:3.18"])


def test_markdown_does_not_render_scanner_html_or_links(args, scanners):
    _, report = scan(args, scanners)
    report["findings"][0]["title"] = '<script>alert(1)</script> [click](javascript:alert(1))\x1b'
    rendered = markdown(redact(report, set()))
    assert "<script>" not in rendered and "[click](" not in rendered and "\x1b" not in rendered


@pytest.mark.parametrize("raw", [[1], {"Results": [{"Target": "../escape"}]}])
def test_invalid_scanner_structure_rejected(raw, repo):
    with pytest.raises(ScanError):
        normalize_trivy(raw, "repo", repo)


def test_redaction_recovers_masked_token_for_other_fields(repo):
    raw = recording("repository")
    token = (repo / "config.env").read_text().split("GH_TOKEN=")[1].strip()
    _, secrets, _ = normalize_trivy(raw, str(repo), repo)
    assert token in secrets
    assert token not in json.dumps(redact({"value": f"prefix {token} suffix"}, secrets))


def test_inventory_merges_multiple_scanners_on_same_file():
    report = {"Results": [{"Target": "requirements.txt", "Packages": [{"Name": "requests", "Version": "2.31.0"}]},
                          {"Target": "requirements.txt", "Secrets": []}]}
    assert package_inventory(report)["requirements.txt"] == {("requests", "2.31.0")}


def test_sbom_special_file_rejected_without_opening(tmp_path):
    fifo = tmp_path / "input.json"
    os.mkfifo(fifo)
    with pytest.raises(ScanError, match="regular"):
        read_sbom(fifo)


def test_cyclonedx_scoped_and_nested_components(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"name": "parent", "version": "1", "components": [{"name": "child", "group": "@scope", "version": "2"}]}]}))
    _, kind, packages = read_sbom(path)
    assert len(packages) == 2
    report = {"Results": [{"Target": "npm", "Packages": [{"Name": "parent", "Version": "1"}, {"Name": "@scope/child", "Version": "2"}]}]}
    assert not sbom_coverage(kind, packages, report)


@pytest.mark.parametrize("manifest,content,lock,lock_content", [
    ("package.json", '{"dependencies":{"lodash":"4.17.20"}}', "package-lock.json", '{"lockfileVersion":3,"packages":{}}'),
    ("pyproject.toml", '[project]\ndependencies=["requests==2.31.0"]', "uv.lock", 'version=1\npackage=[]'),
    ("pyproject.toml", '[project]\ndependencies=["requests==2.31.0"]', "requirements.txt", ''),
])
def test_empty_lockfile_cannot_hide_manifest_dependencies(tmp_path, manifest, content, lock, lock_content):
    (tmp_path / manifest).write_text(content)
    (tmp_path / lock).write_text(lock_content)
    notes = repository_coverage(tmp_path, {"Results": []})
    assert any("ausentes no inventário" in note for note in notes)
