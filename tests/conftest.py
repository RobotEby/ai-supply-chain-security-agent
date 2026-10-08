import copy
import json
from pathlib import Path
import shutil

import pytest

from sc_agent.cli import parser


FIXTURES = Path(__file__).parent / "fixtures"


def recording(name):
    return json.loads((FIXTURES / "recordings" / f"{name}.json").read_text())


class RecordedScanners:
    """Reproduz respostas reais; reanálises de patches têm resposta fornecida pelo teste."""
    def __init__(self):
        self.metadata = recording("metadata")
        self.calls = []
        self.after_requirements = None
        self.after_zizmor = None
        self.patch_workflow = None

    def trivy(self, kind, target, cwd):
        self.calls.append((kind, target))
        if kind == "fs" and Path(target).name == "candidate":
            if self.after_requirements is not None:
                return copy.deepcopy(self.after_requirements)
            return recording("repository")
        if kind == "fs":
            return recording("repository")
        if kind == "image":
            return recording("image")
        data = json.loads(Path(target).read_text())
        return recording("cyclonedx" if "bomFormat" in data else "spdx")

    def zizmor(self, root, cwd, fix=False):
        self.calls.append(("zizmor-fix" if fix else "zizmor", root))
        if fix and self.patch_workflow:
            path, content = self.patch_workflow
            (root / path).write_text(content)
        if Path(root).name == "candidate" and self.after_zizmor is not None:
            return copy.deepcopy(self.after_zizmor)
        return recording("zizmor")


@pytest.fixture
def repo(tmp_path):
    destination = tmp_path / "repo"
    shutil.copytree(FIXTURES / "repo", destination)
    return destination


@pytest.fixture
def scanners():
    return RecordedScanners()


@pytest.fixture
def args(tmp_path, repo):
    return parser().parse_args(["scan", "--repo", str(repo), "--out", str(tmp_path / "report")])
