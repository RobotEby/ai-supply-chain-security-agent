import json
import os
from pathlib import Path

import pytest

from sc_agent.scanners import ScanError, Scanners


def executable(tmp_path, content):
    path = tmp_path / "scanner"
    path.write_text("#!/usr/bin/env python3\n" + content)
    path.chmod(0o755)
    scanners = Scanners(timeout=2)
    scanners.executables["trivy"] = str(path)
    return scanners


def test_arguments_are_not_shell_code_and_env_is_restricted(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "never-send")
    monkeypatch.setenv("TRIVY_IGNORE_UNFIXED", "true")
    scanners = executable(tmp_path, "import json,sys,os\nprint(json.dumps({'args':sys.argv[1:],'github':os.getenv('GITHUB_TOKEN'),'override':os.getenv('TRIVY_IGNORE_UNFIXED')}))\n")
    result = scanners.json("trivy", ["$(touch pwned)", "file with spaces"], tmp_path)
    assert result["args"] == ["$(touch pwned)", "file with spaces"]
    assert result["github"] is None and result["override"] is None
    assert not (tmp_path / "pwned").exists()


def test_tool_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(ScanError, match="ausente"):
        Scanners().run("trivy", [], tmp_path)


def test_timeout(tmp_path):
    scanners = executable(tmp_path, "import time\ntime.sleep(10)\n")
    scanners.timeout = 0.02
    with pytest.raises(ScanError, match="limite"):
        scanners.run("trivy", [], tmp_path)


def test_stderr_and_stdout_never_expose_secret_on_error(tmp_path):
    scanners = executable(tmp_path, "import sys\nprint('private-output')\nprint('secret-password',file=sys.stderr)\nsys.exit(1)\n")
    with pytest.raises(ScanError) as error:
        scanners.run("trivy", [], tmp_path)
    assert "secret-password" not in str(error.value) and "private-output" not in str(error.value)


def test_invalid_json(tmp_path):
    scanners = executable(tmp_path, "print('not-json')\n")
    with pytest.raises(ScanError, match="JSON inválido"):
        scanners.json("trivy", [], tmp_path)


def test_incompatible_binary_rejected(tmp_path, monkeypatch):
    scanners = Scanners()
    monkeypatch.setattr(scanners, "run", lambda *a: '{"Version":"0.69.4"}')
    with pytest.raises(ScanError, match="incompatível"):
        scanners.check("trivy", tmp_path)


@pytest.mark.parametrize("kind", ["fs", "image", "sbom"])
def test_correct_flags_for_each_trivy_command(tmp_path, monkeypatch, kind):
    scanners = Scanners()
    captured = []
    monkeypatch.setattr(scanners, "check", lambda *a: None)
    def result(name, args, cwd):
        captured.append(args)
        return {"SchemaVersion": 2} if args[0] != "version" else {"Version": "0.75.0"}
    monkeypatch.setattr(scanners, "json", result)
    scanners.trivy(kind, "input", tmp_path)
    args = captured[0]
    assert ("--include-dev-deps" in args) == (kind == "fs")
    assert ("--secret-config" in args) == (kind != "sbom")
    assert ("--image-config-scanners" in args) == (kind == "image")
    assert args[-2:] == ["--", "input"]
