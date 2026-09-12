"""Geracao de relatorio: markdown + JSON, com analise opcional por LLM.

O relatorio e o produto final do ciclo (recon -> achados -> priorizacao ->
remediacao). Sem LLM ele ja e util; com LLM, o adapter devolve um bloco
JSON (resumo/prioridades/proximos_passos) que e injetado no markdown.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .llm import LLMClient, SYSTEM_PROMPT, build_prompt, get_client
from .mitre import describe
from .storage import Finding, findings_by_severity

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
BADGE = {
    "critical": "🔴 CRÍTICO",
    "high": "🟠 ALTO",
    "medium": "🟡 MÉDIO",
    "low": "🔵 BAIXO",
    "info": "⚪ INFO",
}


def _sev_key(f: dict) -> int:
    return SEV_ORDER.index(f.get("severity", "info")) if f.get("severity") in SEV_ORDER else 99


def render_json(findings: list[Finding], target: str, meta: dict | None = None) -> str:
    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta or {},
        "counts": findings_by_severity([f.__dict__ for f in findings]),
        "findings": [f.__dict__ for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_markdown(
    findings: list[Finding],
    target: str,
    llm_block: dict | None = None,
    meta: dict | None = None,
) -> str:
    rows = sorted([f.__dict__ for f in findings], key=_sev_key)
    counts = findings_by_severity(rows)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = []
    out.append(f"# Relatório Red Team — `{target}`\n")
    out.append(f"Gerado em {now}\n")

    if llm_block:
        out.append("## Resumo executivo (LLM)\n")
        out.append(llm_block.get("resumo", "").strip() + "\n")
        prios = llm_block.get("prioridades") or []
        if prios:
            out.append("### Prioridades\n")
            for p in prios:
                out.append(
                    f"- **{p.get('titulo','')}** ({p.get('severidade','')}) — "
                    f"{p.get('racional','')} _Remediação:_ {p.get('remediacao','')}"
                )
            out.append("")
        nxt = llm_block.get("proximos_passos") or []
        if nxt:
            out.append("### Próximos passos\n")
            out.extend(f"- {n}" for n in nxt)
            out.append("")

    out.append("## Distribuição por severidade\n")
    out.append("| Severidade | Quantidade |")
    out.append("|---|---|")
    for sev in SEV_ORDER:
        if counts.get(sev):
            out.append(f"| {BADGE.get(sev, sev)} | {counts[sev]} |")
    if not counts:
        out.append("| — | 0 |")
    out.append("")

    out.append("## Achados\n")
    if not rows:
        out.append("_Nenhum achado registrado._\n")
    for f in rows:
        sev = f.get("severity", "info")
        out.append(f"### {BADGE.get(sev, sev)} — {f.get('title','')}\n")
        out.append(f"- **Módulo:** `{f.get('module','')}`")
        if f.get("mitre"):
            out.append(f"- **MITRE ATT&CK:** {describe(f['mitre'])}")
        if f.get("detail"):
            out.append(f"- **Detalhe:** {f['detail']}")
        if f.get("evidence"):
            ev = str(f["evidence"]).replace("\n", " ")
            out.append(f"- **Evidência:** `{ev[:300]}`")
        out.append("")

    if meta:
        out.append("## Metadados da execução\n")
        out.append("```json")
        out.append(json.dumps(meta, ensure_ascii=False, indent=2))
        out.append("```\n")

    out.append("---\n")
    out.append(
        "> Relatório gerado por redteam-cli em ambiente de laboratório. "
        "Todos os alvos testados são próprios ou explicitamente autorizados."
    )
    return "\n".join(out)


def llm_analysis(findings: Iterable[Finding], target: str,
                 client: LLMClient | None = None,
                 prefer: str = "auto") -> dict | None:
    """Chama o LLM e devolve o bloco parseado (ou None se nao der)."""
    client = client or get_client(prefer)
    rows = [f.__dict__ for f in findings]
    if not rows:
        return None
    raw = client.complete(SYSTEM_PROMPT, build_prompt(rows, target))
    try:
        start, end = raw.find("{"), raw.rfind("}")
        if start >= 0 and end > start:
            return json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        pass
    return {"resumo": raw[:2000], "prioridades": [], "proximos_passos": []}


def write_report(path: Path, markdown: str, json_payload: str | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
    if json_payload:
        path.with_suffix(".json").write_text(json_payload, encoding="utf-8")
    return path
