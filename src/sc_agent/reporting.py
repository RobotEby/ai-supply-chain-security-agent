import html
import json
from pathlib import Path


def escape(value):
    text = html.escape(str(value), quote=False)
    for char in ("\\", "`", "*", "_", "[", "]", "|", "#", "!"):
        text = text.replace(char, "\\" + char)
    return text.replace("\n", " ").replace("\r", " ")


def markdown(report):
    lines = ["# Relatório de segurança", "", f"Estado: **{report['status']}** · Achados: **{len(report['findings'])}**", "",
             "Os achados refletem os scanners e suas bases. Ausência de achados não comprova ausência de riscos.", "", "## Alvos", ""]
    for target in report["targets"]:
        lines.append(f"- {escape(target['kind'])}: {escape(target['input'])} — **{target['status']}**")
        for note in target["notes"]:
            lines.append(f"  - {escape(note)}")
    if report["warnings"]:
        lines += ["", "## Avisos", ""] + [f"- {escape(w)}" for w in report["warnings"]]
    lines += ["", "## Achados", ""]
    for f in report["findings"]:
        lines += [f"### {escape(f['severity'])} · {escape(f['rule'])} · {escape(f['title'])}", "",
                  f"ID: {f['id']} · Fonte: {escape(f['source'])} · Severidade original: {escape(f['original_severity'])}", "",
                  escape(f["evidence"]), "", escape(f["recommendation"]), ""]
        if f["fixed_versions"]:
            lines += ["Versões corrigidas informadas: " + escape(", ".join(f["fixed_versions"])), ""]
        for loc in f["locations"]:
            lines.append(f"- {escape(loc['target'])} → {escape(loc['path'])}" + (f":{loc['line']}" if loc.get("line") else ""))
        if f["reference"]:
            lines += ["", "Referência: " + escape(f["reference"])]
        lines.append("")
    lines += ["## Patches para revisão manual", "", "Nenhum patch foi aplicado aos arquivos originais.", ""]
    for patch in report["patches"]:
        lines += [f"- {escape(patch['file'])}: {escape(patch['reason'])}",
                  f"  - Achados: {', '.join(patch['finding_ids'])}", f"  - {escape(patch['validation'])}"]
    if report["ai"]["explanations"]:
        lines += ["", "## Explicações da IA — não verificadas", ""]
        for item in report["ai"]["explanations"]:
            lines += [f"- {escape(item['finding_id'])}: {escape(item['explanation'])}", f"  - {escape(item['recommendation'])}"]
    lines += ["", "## Ferramentas e bases", "", "```json", json.dumps(report["tools"], indent=2, ensure_ascii=False).replace("`", "\\u0060"), "```", ""]
    return "\n".join(lines)


def write_report(output: Path, report, patches):
    for patch in patches:
        path = output / patch["file"]
        path.parent.mkdir(exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(patch["content"])
    with (output / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    with (output / "report.md").open("x", encoding="utf-8") as stream:
        stream.write(markdown(report))
