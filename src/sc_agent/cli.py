import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import tempfile

from .ai import explain
from .inputs import read_sbom, repository_coverage, sbom_coverage, snapshot, valid_image, workflow_files
from .models import SEVERITIES, group_findings, redact
from .patches import propose_patches
from .reporting import write_report
from .scanners import ScanError, Scanners, normalize_trivy, normalize_zizmor


def parser():
    cli = argparse.ArgumentParser(prog="sc-agent", description="Analisa a cadeia de software e propõe correções para revisão humana.")
    commands = cli.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Analisar repositório, imagens e SBOMs")
    scan.add_argument("--repo", type=Path, help="Diretório local do repositório")
    scan.add_argument("--image", action="append", default=[], help="Referência de imagem existente; repetível")
    scan.add_argument("--sbom", type=Path, action="append", default=[], help="SBOM JSON local; repetível")
    scan.add_argument("--out", type=Path, required=True, help="Diretório novo ou vazio para relatórios e patches")
    scan.add_argument("--ai-model", help="Modelo local instalado no Ollama; IA desativada por padrão")
    scan.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none", help="Severidade mínima que bloqueia o CI (padrão: none)")
    return cli


def scan(args, scanners=None):
    scanners = scanners or Scanners()
    output = args.out.expanduser().resolve()
    repository = args.repo.expanduser().resolve() if args.repo else None
    if repository and (output == repository or output in repository.parents):
        raise ScanError("O diretório de saída não pode ser o próprio repositório ou seu ancestral.")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ScanError("O diretório de saída deve ser novo ou vazio; nenhum arquivo existente será sobrescrito.")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
              "status": "complete", "targets": [], "findings": [], "patches": [], "tools": {},
              "warnings": [], "policy": {"fail_on": args.fail_on},
              "ai": {"enabled": bool(args.ai_model), "model": args.ai_model, "explanations": []}}
    findings, secrets, proposals = [], set(), []

    def target(kind, value):
        entry = {"kind": kind, "input": str(value), "status": "complete", "notes": [], "packages_scanned": 0}
        report["targets"].append(entry)
        return entry

    def failed(entry, error):
        entry["status"] = "incomplete"
        entry["notes"].append(str(error))

    def trivy(kind, value, entry, work, root=None):
        raw = scanners.trivy(kind, value, work)
        normalized, detected, sensitive = normalize_trivy(raw, entry["input"], root)
        findings.extend(normalized)
        secrets.update(detected)
        entry["packages_scanned"] = sum(len(r.get("Packages", []) or []) for r in raw.get("Results", []) or [])
        return raw, normalized, sensitive

    with tempfile.TemporaryDirectory(prefix="sc-agent-") as temporary:
        work = Path(temporary)
        if repository:
            entry = target("repo", repository)
            root = work / "repository"
            local_findings, sensitive = [], set()
            copied = False
            try:
                if not repository.is_dir():
                    raise ScanError("Repositório ausente ou não é um diretório.")
                entry["notes"].extend(snapshot(repository, root, output))
                copied = True
                raw, normalized, sensitive = trivy("fs", root, entry, work, root)
                local_findings.extend(normalized)
                entry["notes"].extend(repository_coverage(root, raw))
            except (ScanError, OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
                failed(entry, error if isinstance(error, ScanError) else "Não foi possível copiar ou validar os arquivos do repositório.")
            if copied and workflow_files(root):
                try:
                    normalized = normalize_zizmor(scanners.zizmor(root, work), entry["input"], root)
                    findings.extend(normalized)
                    local_findings.extend(normalized)
                    sensitive.update(loc["path"] for f in normalized if f.rule == "hardcoded-container-credentials" for loc in f.locations)
                    report["warnings"].append("GitHub Actions: apenas análises offline; referências remotas não são inspecionadas.")
                except ScanError as error:
                    failed(entry, error)
            if entry["notes"]:
                entry["status"] = "incomplete"
            if entry["status"] == "complete":
                try:
                    proposed, warnings = propose_patches(root, entry["input"], local_findings, sensitive, secrets, scanners, work)
                    proposals.extend(proposed)
                    report["warnings"].extend(warnings)
                except (OSError, UnicodeError) as error:
                    report["warnings"].append("Não foi possível gerar patches; os achados permanecem disponíveis.")
            report["warnings"].append("Repositório: excluídos .git, ambientes virtuais, node_modules, caches e saída. requirements.txt cobre apenas versões declaradas; dependências transitivas precisam estar resolvidas no arquivo.")

        for reference in dict.fromkeys(args.image):
            entry = target("image", reference if valid_image(reference) else "[referência inválida]")
            try:
                if not valid_image(reference):
                    raise ScanError("Referência de imagem inválida; use nome[:tag] ou nome@sha256:digest, sem credenciais.")
                raw, _, _ = trivy("image", reference, entry, work)
                metadata = raw.get("Metadata") or {}
                if not isinstance(metadata, dict):
                    raise ScanError("trivy: metadados da imagem inválidos.")
                entry["image_id"] = metadata.get("ImageID")
                entry["repo_digests"] = metadata.get("RepoDigests", [])
                if not entry["packages_scanned"]:
                    entry["notes"].append("Nenhum pacote reconhecido na imagem; vulnerabilidades de componentes não puderam ser avaliadas.")
                    entry["status"] = "incomplete"
                if (metadata.get("OS") or {}).get("EOSL"):
                    report["warnings"].append("Imagem com sistema operacional fora de suporte; a cobertura de vulnerabilidades pode estar desatualizada.")
            except ScanError as error:
                failed(entry, error)

        for index, source in enumerate(dict.fromkeys(args.sbom)):
            entry = target("sbom", source.expanduser().resolve())
            try:
                data, kind, packages = read_sbom(source.expanduser())
                copied_sbom = work / f"sbom-{index}.json"
                copied_sbom.write_text(json.dumps(data), encoding="utf-8")
                raw, _, _ = trivy("sbom", copied_sbom, entry, work)
                entry["format"] = kind
                entry["notes"].extend(sbom_coverage(kind, packages, raw))
                if entry["notes"]:
                    entry["status"] = "incomplete"
            except (ScanError, OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
                failed(entry, error if isinstance(error, ScanError) else "Não foi possível ler ou validar o SBOM.")
        if args.sbom:
            report["warnings"].append("SBOMs de terceiros podem omitir metadados necessários ao scanner. A análise não verifica assinatura, completude ou correspondência com uma imagem.")

    report["findings"] = redact(group_findings(findings), secrets)
    report["tools"] = scanners.metadata
    if args.ai_model:
        report["ai"]["explanations"], warnings = explain(report["findings"], args.ai_model)
        report["warnings"].extend(warnings)
    safe_patches = []
    for proposal in proposals:
        # Segredos de alvos posteriores também não podem aparecer em patches anteriores.
        if any(secret and secret in proposal["content"] for secret in secrets):
            report["warnings"].append("Um patch foi omitido por conter um segredo detectado em outro alvo.")
            continue
        proposal["file"] = f"patches/{len(safe_patches) + 1:03d}.patch"
        safe_patches.append(proposal)
        report["patches"].append({k: v for k, v in proposal.items() if k != "content"})
    if any(t["status"] == "incomplete" for t in report["targets"]):
        report["status"] = "incomplete"
    report = redact(report, secrets)
    write_report(output, report, safe_patches)
    if report["status"] == "incomplete":
        code = 2
    elif args.fail_on != "none" and any(SEVERITIES[f["severity"]] >= SEVERITIES[args.fail_on.upper()] for f in report["findings"]):
        code = 1
    else:
        code = 0
    return code, report


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if not (args.repo or args.image or args.sbom):
        cli.error("informe pelo menos um alvo: --repo, --image ou --sbom")
    if args.ai_model and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:+-]{0,199}", args.ai_model) or "cloud" in args.ai_model.lower()):
        cli.error("--ai-model deve identificar um modelo local instalado, sem modo cloud")
    try:
        code, report = scan(args)
        print(f"Análise {report['status']}: {len(report['findings'])} achados; {len(report['patches'])} patches para revisão. Relatórios gravados no diretório de saída.")
        return code
    except ScanError as error:
        print(f"Erro: {error}", file=sys.stderr)
    except OSError:
        print("Erro ao acessar arquivos ou gravar relatórios. Verifique permissões e espaço disponível.", file=sys.stderr)
    return 2
