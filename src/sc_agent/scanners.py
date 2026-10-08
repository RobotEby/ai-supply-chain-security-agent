import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .models import Finding


VERSIONS = {"trivy": "0.75.0", "zizmor": "1.30.1"}
MAX_OUTPUT = 64 * 1024 * 1024


class ScanError(Exception):
    """Erro operacional seguro para apresentar, sem stderr ou conteúdo do alvo."""


class Scanners:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.metadata = {}
        self.executables = {}

    def run(self, name: str, args: list[str], cwd: Path) -> str:
        executable = self.executables.get(name) or shutil.which(name)
        if not executable:
            raise ScanError(f"{name}: executável ausente; execute scripts/install_scanners.py e ajuste PATH.")
        executable = str(Path(executable).resolve())
        # Credenciais só chegam ao scanner de imagens; configurações de scanner via env não são herdadas.
        allowed = {"PATH", "HOME", "XDG_CACHE_HOME", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                   "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"}
        if name == "trivy":
            allowed |= {"DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
                        "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        env["NO_COLOR"] = "1"
        try:
            with tempfile.TemporaryFile() as output:
                completed = subprocess.run(
                    [executable, *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.DEVNULL, timeout=self.timeout, check=False,
                )
                if completed.returncode:
                    raise ScanError(f"{name}: falha operacional (código {completed.returncode}); verifique o alvo, acesso ao registry e às bases.")
                output.seek(0)
                data = output.read(MAX_OUTPUT + 1)
                if len(data) > MAX_OUTPUT:
                    raise ScanError(f"{name}: resultado excede o limite de 64 MiB; divida os alvos.")
                return data.decode("utf-8")
        except subprocess.TimeoutExpired:
            raise ScanError(f"{name}: tempo limite de {self.timeout}s excedido.") from None
        except (OSError, UnicodeError):
            raise ScanError(f"{name}: não foi possível executar ou ler o resultado.") from None

    def json(self, name, args, cwd):
        try:
            return json.loads(self.run(name, args, cwd))
        except (json.JSONDecodeError, RecursionError):
            raise ScanError(f"{name}: JSON inválido.") from None

    def check(self, name, cwd):
        if name in self.executables:
            return
        if name == "trivy":
            info = self.json(name, ["version", "--format", "json"], cwd)
            version = info.get("Version") if isinstance(info, dict) else None
        else:
            version = self.run(name, ["--version"], cwd).strip().removeprefix("zizmor ")
            info = {"Version": version}
        if version != VERSIONS[name]:
            raise ScanError(f"{name}: versão incompatível; use {VERSIONS[name]}.")
        self.metadata[name] = info
        self.executables[name] = str(Path(shutil.which(name)).resolve())

    def trivy(self, kind, target, cwd):
        self.check("trivy", cwd)
        args = [kind, "--config", "", "--ignorefile", "",
                "--disable-telemetry", "--skip-version-check", "--quiet", "--no-progress",
                "--format", "json", "--timeout", f"{self.timeout}s", "--offline-scan"]
        if kind == "sbom":
            args += ["--scanners", "vuln"]
        else:
            args += ["--scanners", "vuln,misconfig,secret", "--secret-config", "", "--misconfig-scanners", "dockerfile"]
        if kind == "fs":
            args.append("--include-dev-deps")
        if kind == "image":
            args += ["--image-config-scanners", "misconfig,secret", "--image-src", "docker,remote"]
        report = self.json("trivy", [*args, "--", str(target)], cwd)
        if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
            raise ScanError("trivy: formato de relatório incompatível.")
        results = report.get("Results", []) or []
        if not isinstance(results, list) or any(not isinstance(result, dict) for result in results):
            raise ScanError("trivy: lista de resultados inválida.")
        for result in results:
            for key in ("Packages", "Vulnerabilities", "Misconfigurations", "Secrets"):
                items = result.get(key, []) or []
                if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                    raise ScanError("trivy: estrutura de resultado inválida.")
        self.metadata["trivy"] = self.json("trivy", ["version", "--format", "json"], cwd)
        return report

    def zizmor(self, root, cwd, fix=False):
        from .inputs import workflow_files

        self.check("zizmor", cwd)
        args = ["--offline", "--no-config", "--no-ignores", "--no-exit-codes", "--no-progress",
                "--strict-collection", "--persona", "auditor", "--collect", "workflows", "--collect", "actions",
                "--format", "json-v1"]
        if fix:
            args.append("--fix=safe")
        return self.json("zizmor", [*args, "--", *(str(p) for p in workflow_files(root))], cwd)


def relative_path(value, root):
    value = str(value)
    if root and Path(value).is_absolute():
        try:
            return Path(value).relative_to(root).as_posix()
        except ValueError:
            raise ScanError("Scanner retornou uma localização fora da cópia analisada.") from None
    if root and ".." in Path(value).parts:
        raise ScanError("Scanner retornou uma localização inválida.")
    return value


def normalize_trivy(report, target, root=None):
    findings, secrets, secret_paths = [], set(), set()
    try:
        results = report.get("Results", []) or []
        for result in results:
            path = relative_path(result["Target"], root)
            ecosystem = result.get("Type", "")
            for item in result.get("Vulnerabilities", []) or []:
                severity = item["Severity"]
                fixed = [v.strip() for v in item.get("FixedVersion", "").split(",") if v.strip()]
                recommendation = "Sem versão corrigida informada; avalie mitigação ou substituição do componente."
                if fixed:
                    recommendation = "Atualize para uma versão corrigida indicada pelo scanner e execute os testes do projeto."
                    if ecosystem in {"npm", "uv"}:
                        recommendation += " Regenere o lockfile com o gerenciador de pacotes."
                    elif root is None:
                        recommendation += " Corrija o componente na origem e gere uma nova imagem/SBOM."
                findings.append(Finding(
                    "trivy", "vulnerability", item["VulnerabilityID"], severity, severity,
                    item.get("Title") or item["VulnerabilityID"],
                    f"{item['PkgName']} {item['InstalledVersion']} identificado em {ecosystem}.",
                    recommendation, item.get("PrimaryURL", ""),
                    [{"target": target, "path": path, "line": None, "original_severity": severity, "ecosystem": ecosystem}],
                    item["PkgName"], item["InstalledVersion"], fixed,
                ))
            for item in result.get("Misconfigurations", []) or []:
                if item.get("Status", "FAIL") != "FAIL":
                    continue
                severity = item["Severity"]
                findings.append(Finding(
                    "trivy", "misconfiguration", item["ID"], severity, severity, item["Title"],
                    "Configuração reprovada pela regra do scanner.", item.get("Resolution", "Revise a configuração e a referência da regra."),
                    item.get("PrimaryURL", ""),
                    [{"target": target, "path": path, "line": item.get("CauseMetadata", {}).get("StartLine"), "original_severity": severity}],
                ))
            for item in result.get("Secrets", []) or []:
                secret_paths.add(path)
                match = item.get("Match", "")
                if match:
                    secrets.add(match)
                # O scanner pode mascarar Match; mantenha linhas originais apenas em memória para redigir dados.
                if root:
                    source = root / path
                    if source.is_file():
                        lines = source.read_text(errors="replace").splitlines()
                        for line in lines[max(0, item.get("StartLine", 1) - 1):item.get("EndLine", item.get("StartLine", 1))]:
                            if line.strip():
                                secrets.add(line.strip())
                        for code in item.get("Code", {}).get("Lines", []):
                            number = code.get("Number", 0)
                            if code.get("IsCause") and 0 < number <= len(lines):
                                for hidden in re.finditer(r"\*{3,}", code.get("Content", "")):
                                    secrets.add(lines[number - 1][hidden.start():hidden.end()])
                severity = item["Severity"]
                findings.append(Finding(
                    "trivy", "secret", item["RuleID"], severity, severity,
                    "Possível segredo exposto", "Conteúdo removido; verifique a localização indicada.",
                    "Revogue e rotacione a credencial, remova-a do código e avalie o histórico de exposição.",
                    "https://trivy.dev/docs/latest/guide/scanner/secret/",
                    [{"target": target, "path": path, "line": item.get("StartLine"), "original_severity": severity}],
                ))
    except (KeyError, TypeError, AttributeError, ValueError, OSError):
        raise ScanError("trivy: estrutura de resultado inválida.") from None
    return findings, secrets, secret_paths


REMEDIATIONS = {
    "excessive-permissions": "Reduza permissions ao mínimo necessário, preferencialmente por job.",
    "unpinned-uses": "Revise o código da action e fixe a referência em um SHA completo verificado.",
    "template-injection": "Passe entradas não confiáveis por variáveis de ambiente e use aspas no shell.",
    "dangerous-triggers": "Separe tarefas privilegiadas da execução de código de pull requests não confiáveis.",
    "artipacked": "Revise a necessidade de persistir credenciais no checkout e os caminhos enviados aos artefatos.",
    "hardcoded-container-credentials": "Rotacione as credenciais e substitua valores literais por secrets do GitHub.",
    "unsound-condition": "Corrija a expressão condicional para que ela produza um booleano.",
}


def normalize_zizmor(report, target, root):
    findings = []
    try:
        if not isinstance(report, list):
            raise ValueError()
        for item in report:
            severity = item["determinations"]["severity"]
            locations = []
            for location in item["locations"]:
                symbolic = location["symbolic"]
                if symbolic.get("kind") == "Hidden":
                    continue
                path = relative_path(symbolic["key"]["Local"]["verbatim_path"], root)
                locations.append({"target": target, "path": path,
                                  "line": location["concrete"]["location"]["start_point"]["row"] + 1,
                                  "original_severity": severity})
            if not locations:
                raise ValueError()
            findings.append(Finding(
                "zizmor", "pipeline", item["ident"], severity, severity, item["desc"],
                f"Regra de workflow; confiança {item['determinations']['confidence']}.",
                REMEDIATIONS.get(item["ident"], "Revise o workflow conforme a documentação da regra e valide seu comportamento."),
                item["url"], locations,
            ))
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ScanError("zizmor: estrutura de resultado inválida.") from None
    return findings
