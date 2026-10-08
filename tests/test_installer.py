import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest


@pytest.fixture
def installer(monkeypatch):
    spec = importlib.util.spec_from_file_location("installer", Path(__file__).parents[1] / "scripts/install_scanners.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    return module


def tarball(link=False):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        binary = tarfile.TarInfo("release/trivy")
        if link:
            binary.type = tarfile.SYMTYPE
            binary.linkname = "/tmp/untrusted"
            tar.addfile(binary)
        else:
            binary.size = 6
            tar.addfile(binary, io.BytesIO(b"binary"))
        escape = tarfile.TarInfo("../../pwned")
        escape.size = 3
        tar.addfile(escape, io.BytesIO(b"bad"))
    return buffer.getvalue()


def configure(module, monkeypatch, data, checksum=None):
    monkeypatch.setattr(module, "RELEASES", {"trivy": ("https://example.invalid", checksum or hashlib.sha256(data).hexdigest())})
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(data))


def test_checksum_mismatch_preserves_existing_executable(installer, monkeypatch, tmp_path):
    destination = tmp_path / "bin"
    destination.mkdir()
    (destination / "trivy").write_text("original")
    configure(installer, monkeypatch, tarball(), "0" * 64)
    with pytest.raises(SystemExit, match="Checksum"):
        installer.install(destination)
    assert (destination / "trivy").read_text() == "original"


def test_only_binary_bytes_extracted_without_archive_paths(installer, monkeypatch, tmp_path):
    configure(installer, monkeypatch, tarball())
    installer.install(tmp_path / "bin")
    assert (tmp_path / "bin/trivy").read_bytes() == b"binary"
    assert list(tmp_path.rglob("*")) == [tmp_path / "bin", tmp_path / "bin/trivy"]
    assert (tmp_path / "bin/trivy").stat().st_mode & 0o111


def test_archive_symlink_cannot_be_installed(installer, monkeypatch, tmp_path):
    configure(installer, monkeypatch, tarball(link=True))
    with pytest.raises(SystemExit, match="inesperado"):
        installer.install(tmp_path / "bin")
    assert not (tmp_path / "bin/trivy").exists()
