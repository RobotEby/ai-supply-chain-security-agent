from collections import Counter, defaultdict
import difflib
from pathlib import Path
import re
import shutil
import tempfile

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .inputs import repository_coverage, workflow_files
from .scanners import ScanError, normalize_trivy, normalize_zizmor


PIN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)(?P<newline>\r?\n)?\Z")


def occurrences(findings):
    return Counter((f.source, f.rule, f.package, loc["path"]) for f in findings for loc in f.locations)


def diff(path, before, after):
    # Diffs sem newline final e nomes ambíguos não são emitidos nesta versão.
    if not before.endswith("\n") or not after.endswith("\n") or any(c in path for c in "\n\r\t\\\""):
        return ""
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile=f"a/{path}", tofile=f"b/{path}"))


def propose_patches(root, target, findings, secret_paths, secrets, scanners, work):
    proposals, warnings = [], []
    by_path = defaultdict(list)
    for finding in findings:
        for location in finding.locations:
            if location["target"] == target:
                by_path[location["path"]].append(finding)

    def emit(path, before, after, resolved, reason):
        patch = diff(path, before, after)
        if not patch or path in secret_paths or any(secret and secret in patch for secret in secrets):
            warnings.append(f"Patch omitido para {path}: contém segredo detectado ou formato de diff não suportado.")
            return
        proposals.append({"path": path, "finding_ids": sorted({f.id for f in resolved}),
                          "reason": reason, "validation": "Reanalisado na cópia temporária; revisão e testes funcionais pendentes.",
                          "content": patch})

    for path, related in by_path.items():
        if Path(path).name != "requirements.txt" or path in secret_paths:
            continue
        source = root / path
        if not source.is_file():
            continue
        before = source.read_bytes().decode("utf-8")
        lines = before.splitlines(keepends=True)
        parsed = []
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = PIN.fullmatch(line)
            if not match:
                break
            parsed.append(match)
        else:
            names = [canonicalize_name(m["name"]) for m in parsed]
            if len(names) != len(set(names)):
                continue
            changes, resolved = {}, []
            for match in parsed:
                affected = [f for f in related if f.category == "vulnerability" and canonicalize_name(f.package) == canonicalize_name(match["name"]) and f.installed_version == match["version"]]
                if not affected or any(len(f.fixed_versions) != 1 for f in affected):
                    continue
                try:
                    versions = [Version(f.fixed_versions[0]) for f in affected]
                    selected = max(versions)
                    if any(v.is_prerelease or v.is_devrelease for v in versions) or selected <= Version(match["version"]):
                        continue
                except InvalidVersion:
                    continue
                changes[match[0]] = f"{match['name']}=={selected}{match['newline'] or ''}"
                resolved.extend(affected)
            if not changes:
                continue
            after = "".join(changes.get(line, line) for line in lines)
            with tempfile.TemporaryDirectory(dir=work) as temporary:
                candidate = Path(temporary) / "candidate"
                candidate.mkdir()
                candidate_file = candidate / path
                candidate_file.parent.mkdir(parents=True, exist_ok=True)
                candidate_file.write_bytes(after.encode())
                try:
                    report = scanners.trivy("fs", candidate, work)
                    checked, detected, sensitive = normalize_trivy(report, target, candidate)
                    secrets.update(detected)
                    remaining = occurrences(checked)
                    baseline = occurrences(related)
                    removed = occurrences(resolved)
                    if repository_coverage(candidate, report) or sensitive or remaining - baseline or any(remaining[key] for key in removed):
                        warnings.append(f"Patch de {path} descartado: a reanálise não confirmou a correção sem novos achados.")
                        continue
                    emit(path, before, after, resolved, "Atualização de pins simples para versões corrigidas informadas pelo Trivy.")
                except ScanError as error:
                    warnings.append(f"Patch de {path} não validado: {error}")

    workflows = workflow_files(root)
    if not workflows or not any(f.source == "zizmor" for f in findings):
        return proposals, warnings
    with tempfile.TemporaryDirectory(dir=work) as temporary:
        candidate = Path(temporary) / "candidate"
        candidate.mkdir()
        for source in workflows:
            path = source.relative_to(root)
            copied = candidate / path
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        try:
            scanners.zizmor(candidate, work, fix=True)
            checked = normalize_zizmor(scanners.zizmor(candidate, work), target, candidate)
            for source in workflows:
                path = source.relative_to(root).as_posix()
                before, after = source.read_bytes().decode(), (candidate / path).read_bytes().decode()
                if before == after:
                    continue
                related = [f for f in by_path[path] if f.source == "zizmor"]
                remaining = [f for f in checked if any(loc["path"] == path for loc in f.locations)]
                baseline, updated = occurrences(related), occurrences(remaining)
                if updated - baseline or not baseline - updated:
                    warnings.append(f"Patch de {path} descartado: nenhum achado resolvido ou novos achados encontrados.")
                    continue
                resolved = [f for f in related if not any(key in updated for key in occurrences([f]))]
                if not resolved:
                    continue
                emit(path, before, after, resolved, "Correção classificada como safe pelo zizmor, executada apenas na cópia.")
        except ScanError as error:
            warnings.append(f"Patches de workflows não validados: {error}")
    return proposals, warnings
