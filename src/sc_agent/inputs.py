import json
import os
from pathlib import Path
import re
import stat
import tomllib

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .scanners import ScanError


EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".tools"}
MAX_FILE = 16 * 1024 * 1024
MAX_REPO = 512 * 1024 * 1024


def snapshot(source: Path, destination: Path, output: Path) -> list[str]:
    notes = []
    total = 0
    destination.mkdir()
    def inaccessible(error):
        raise ScanError("Diretório inacessível durante a cópia; cobertura incompleta.")

    for parent, dirs, files in os.walk(source, followlinks=False, onerror=inaccessible):
        parent = Path(parent)
        kept = []
        for name in dirs:
            path = parent / name
            if name in EXCLUDED_DIRS or path.resolve() == output:
                continue
            if path.is_symlink():
                notes.append(f"Link simbólico não analisado: {path.relative_to(source)}")
                continue
            kept.append(name)
        dirs[:] = kept
        for name in files:
            path = parent / name
            relative = path.relative_to(source)
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                notes.append(f"Arquivo especial/link não analisado: {relative}")
                continue
            if metadata.st_size > MAX_FILE:
                notes.append(f"Arquivo maior que 16 MiB não analisado: {relative}")
                continue
            total += metadata.st_size
            if total > MAX_REPO:
                raise ScanError("Repositório excede 512 MiB após exclusões; divida os alvos.")
            # O_NOFOLLOW evita que a troca de um arquivo por um link leia algo fora do alvo.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ScanError("Arquivo mudou de tipo durante a cópia.")
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ScanError("Arquivo cresceu além do limite durante a cópia.")
            copied = destination / relative
            copied.parent.mkdir(parents=True, exist_ok=True)
            copied.write_bytes(data)
    return notes


def workflow_files(root):
    return sorted(p for p in root.rglob("*") if p.is_file() and (
        p.name in {"action.yml", "action.yaml"} or
        (p.suffix in {".yml", ".yaml"} and p.parent.name == "workflows" and p.parent.parent.name == ".github")
    ))


def package_inventory(report):
    inventory = {}
    for result in report.get("Results", []) or []:
        inventory.setdefault(result["Target"], set()).update(
            (canonicalize_name(p["Name"]), str(p["Version"])) for p in result.get("Packages", []) or []
        )
    return inventory


def repository_coverage(root, report):
    notes = []
    inventory = package_inventory(report)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        expected = set()
        try:
            if path.name == "requirements.txt":
                for line in path.read_text().splitlines():
                    line = line.split(" #", 1)[0].strip()
                    if not line or line.startswith("#"):
                        continue
                    requirement = Requirement(line)
                    specs = list(requirement.specifier)
                    if requirement.url or len(specs) != 1 or specs[0].operator != "==" or "*" in specs[0].version:
                        notes.append(f"{relative}: dependência sem versão exata; cobertura pip incompleta.")
                    else:
                        expected.add((canonicalize_name(requirement.name), specs[0].version))
            elif path.name == "package-lock.json":
                content = json.loads(path.read_text())
                if content.get("lockfileVersion") not in {2, 3}:
                    notes.append(f"{relative}: cobertura validada apenas para lockfile npm v2/v3.")
                for key, package in content.get("packages", {}).items():
                    if not key or package.get("link"):
                        continue
                    name = package.get("name") or key.rsplit("node_modules/", 1)[-1]
                    expected.add((canonicalize_name(name), package["version"]))
            elif path.name == "uv.lock":
                content = tomllib.loads(path.read_text())
                for package in content.get("package", []):
                    if "registry" in package.get("source", {}):
                        expected.add((canonicalize_name(package["name"]), package["version"]))
                    elif not any(key in package.get("source", {}) for key in ("virtual", "editable")):
                        notes.append(f"{relative}: dependência de origem não-registry exige revisão manual.")
            elif path.name == "package.json":
                content = json.loads(path.read_text())
                if any(content.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")):
                    # Workspaces podem compartilhar o lockfile de um diretório ancestral.
                    parents = [path.parent, *path.parent.parents]
                    locks = [p / "package-lock.json" for p in parents if (p == root or root in p.parents) and (p / "package-lock.json").is_file()]
                    if not locks:
                        notes.append(f"{relative}: package-lock.json ausente; dependências não resolvidas.")
                    else:
                        resolved = {name for name, _ in inventory.get(locks[0].relative_to(root).as_posix(), set())}
                        declared = {canonicalize_name(name) for key in ("dependencies", "devDependencies", "optionalDependencies")
                                    for name, version in content.get(key, {}).items() if not version.startswith(("workspace:", "file:"))}
                        if declared - resolved:
                            notes.append(f"{relative}: dependências declaradas ausentes no inventário do lockfile.")
            elif path.name == "pyproject.toml":
                content = tomllib.loads(path.read_text())
                project = content.get("project", {})
                has_deps = project.get("dependencies") or project.get("optional-dependencies") or content.get("dependency-groups") or content.get("tool", {}).get("poetry")
                if has_deps and not any((path.parent / f).is_file() for f in ("uv.lock", "requirements.txt")):
                    notes.append(f"{relative}: uv.lock/requirements.txt ausente; dependências não resolvidas.")
                elif has_deps:
                    resolved = {name for filename in ("uv.lock", "requirements.txt") for name, _ in inventory.get((path.parent / filename).relative_to(root).as_posix(), set())}
                    requirements = list(project.get("dependencies", []))
                    for group in project.get("optional-dependencies", {}).values():
                        requirements.extend(group)
                    for group in content.get("dependency-groups", {}).values():
                        requirements.extend(item for item in group if isinstance(item, str))
                    declared = {canonicalize_name(Requirement(value).name) for value in requirements}
                    if declared - resolved:
                        notes.append(f"{relative}: dependências declaradas ausentes no inventário resolvido.")
            if expected - inventory.get(relative, set()):
                notes.append(f"{relative}: o scanner não reconheceu todas as versões declaradas.")
        except (ValueError, KeyError, TypeError, AttributeError, InvalidRequirement):
            notes.append(f"{relative}: manifesto inválido ou não suportado; cobertura incompleta.")
    return notes


def read_sbom(path):
    if not path.is_file():
        raise ScanError("SBOM ausente ou não é um arquivo regular.")
    if path.stat().st_size > MAX_FILE:
        raise ScanError("SBOM excede 16 MiB.")
    try:
        data = json.loads(path.read_text())
        if data.get("bomFormat") == "CycloneDX" and data.get("specVersion") in {"1.4", "1.5", "1.6"}:
            packages = data.get("components", [])
            kind = "CycloneDX"
        elif data.get("spdxVersion") in {"SPDX-2.2", "SPDX-2.3"}:
            packages = data.get("packages", [])
            kind = "SPDX"
        else:
            raise ScanError("Formato de SBOM não suportado; use CycloneDX JSON 1.4–1.6 ou SPDX JSON 2.2/2.3.")
        if not isinstance(packages, list) or any(not isinstance(p, dict) or not p.get("name") for p in packages):
            raise ValueError()
        if kind == "CycloneDX":
            flattened, pending = [], list(packages)
            while pending:
                component = pending.pop()
                if not isinstance(component, dict) or not isinstance(component.get("name"), str):
                    raise ValueError()
                flattened.append(component)
                nested = component.get("components", [])
                if not isinstance(nested, list):
                    raise ValueError()
                pending.extend(nested)
            packages = flattened
        return data, kind, packages
    except (ValueError, TypeError, AttributeError):
        raise ScanError("SBOM JSON inválido.") from None


def sbom_coverage(kind, packages, report):
    inventory = set().union(*package_inventory(report).values()) if report.get("Results") else set()
    expected = set()
    for package in packages:
        name = package["name"]
        if kind == "CycloneDX" and package.get("group", "").startswith("@") and not name.startswith("@"):
            name = f"{package['group']}/{name}"
        expected.add((canonicalize_name(name), str(package.get("version" if kind == "CycloneDX" else "versionInfo", ""))))
    notes = []
    if any(not version for _, version in expected) or expected - inventory:
        notes.append("SBOM contém componentes sem versão ou não reconhecidos pelo scanner; cobertura incompleta.")
    return notes


def valid_image(value):
    # Referência OCI, sem URLs autenticadas, opções ou caracteres de shell.
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}", value)) and value.count("@") <= 1 and "://" not in value and ("@" not in value or re.search(r"@sha256:[a-fA-F0-9]{64}$", value))
