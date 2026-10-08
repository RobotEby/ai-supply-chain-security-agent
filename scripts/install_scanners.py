"""Instala os binários validados para Linux x86_64, verificando SHA-256."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request


RELEASES = {
    "trivy": (
        "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/"
        "trivy_0.75.0_Linux-64bit.tar.gz",
        "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
    ),
    "zizmor": (
        "https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/"
        "zizmor-x86_64-unknown-linux-gnu.tar.gz",
        "e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a",
    ),
}


def install(destination: Path) -> None:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise SystemExit("Instalação automatizada disponível apenas para Linux x86_64.")
    destination.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in RELEASES.items():
        with urllib.request.urlopen(url, timeout=120) as response:
            archive = response.read()
        if hashlib.sha256(archive).hexdigest() != digest:
            raise SystemExit(f"Checksum inválido: {name}. Nenhum binário dessa resposta foi instalado.")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = [m for m in tar.getmembers() if Path(m.name).name == name and m.isfile()]
            if len(members) != 1:
                raise SystemExit(f"Arquivo inesperado: {name}.")
            # Extraímos somente os bytes do executável, nunca caminhos do arquivo tar.
            with tar.extractfile(members[0]) as source:
                binary = source.read()
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
            output.write(binary)
            temporary = Path(output.name)
        temporary.chmod(0o755)
        os.replace(temporary, destination / name)
        print(f"{name}: instalado com SHA-256 verificado")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=Path(".tools/bin"))
    install(parser.parse_args().dest)
