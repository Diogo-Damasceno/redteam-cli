"""CLI do redteam-cli.

  redteam list                       -> modulos registrados
  redteam run <modulo> --target ...  -> executa (respeitando a politica)
  redteam report <run_id>            -> regera relatorio de uma execucao

Alvo e SEMPRE validado pela TargetPolicy antes de qualquer modulo rodar.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .banner import print_banner
from .core.context import Ctx
from .core.guardrails import (
    GuardrailError,
    Sandbox,
    TargetPolicy,
    AuditLog,
    load_allowlist,
)
from .core.registry import all_modules, by_category, load_builtins
from .core.report import llm_analysis, render_json, render_markdown, write_report
from .core.storage import Storage


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redteam",
        description="Framework CLI de red team para laboratorio (alvo fake/local)",
    )
    p.add_argument("--db", default="redteam.db", help="arquivo SQLite de achados")
    p.add_argument("--no-banner", action="store_true", help="oculta o banner ASCII")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="lista os modulos disponiveis")

    r = sub.add_parser("run", help="executa um modulo")
    r.add_argument("module")
    r.add_argument("--target", default="127.0.0.1")
    r.add_argument("--mode", choices=["sim", "live"], default="sim")
    r.add_argument("--i-own-it", action="store_true",
                   help="confirma que o alvo e seu (desbloqueia --mode live)")
    r.add_argument("--targets", help="arquivo de allowlist (1 host por linha)")
    r.add_argument("--sandbox", help="diretorio sandbox para modulos destrutivos")
    r.add_argument("--out", help="arquivo .md do relatorio")
    r.add_argument("--json", action="store_true", help="tambem salva .json")
    r.add_argument("--llm", choices=["auto", "api", "offline", "anthropic", "openai"], default="auto")
    r.add_argument("--no-llm", action="store_true", help="pula analise por LLM")
    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument("--opt", action="append", default=[],
                   help="opcao extra k=v (ex: --opt ports=80,443)")

    rp = sub.add_parser("report", help="regenera relatorio de um run")
    rp.add_argument("run_id", type=int)
    rp.add_argument("--out", required=True)
    rp.add_argument("--llm", choices=["auto", "api", "offline", "anthropic", "openai"], default="auto")

    d = sub.add_parser("dashboard", help="sobe dashboard local dos achados")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8765)

    l = sub.add_parser("llm", help="mostra/diagnostica o adaptador de LLM")
    l.add_argument("--ping", action="store_true",
                   help="faz uma chamada real de teste ao provedor")
    l.add_argument("--provider", choices=["auto", "openai", "anthropic", "offline"],
                   default="auto")

    return p


def _parse_opts(pairs: list[str]) -> dict:
    out: dict = {}
    for item in pairs:
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        if v.lower() in ("true", "false"):
            out[k] = v.lower() == "true"
        else:
            out[k] = v
    return out


def _make_ctx(args) -> Ctx:
    allow = load_allowlist(Path(args.targets)) if getattr(args, "targets", None) else set()
    if getattr(args, "i_own_it", False):
        allow.add(args.target)

    policy = TargetPolicy(
        allowlist=allow,
        lab_only=(getattr(args, "mode", "sim") == "sim"),
        require_confirm=True,
    )
    sandbox = Sandbox(Path(args.sandbox)) if getattr(args, "sandbox", None) else None

    return Ctx(
        target=args.target,
        options=_parse_opts(getattr(args, "opt", [])),
        mode=getattr(args, "mode", "sim"),
        verbose=getattr(args, "verbose", False),
        policy=policy,
        sandbox=sandbox,
        storage=Storage(getattr(args, "db", "redteam.db")),
        audit=AuditLog(Path("audit.jsonl")),
    )


def cmd_list(_args) -> int:
    load_builtins()
    mods = all_modules()
    if not mods:
        print("nenhum modulo registrado")
        return 1
    print(f"{len(mods)} modulos:\n")
    for cls in sorted(mods.values(), key=lambda c: (c.meta.category, c.meta.name)):
        m = cls.meta
        flag = " [DESTRUTIVO]" if m.destructive else ""
        print(f"  {m.name:<12} {m.category:<11}{flag}")
        print(f"    {m.description}")
        if m.mitre:
            print(f"    MITRE: {', '.join(m.mitre)}")
        print()
    return 0


def cmd_run(args) -> int:
    load_builtins()
    cls = all_modules().get(args.module)
    if not cls:
        print(f"modulo desconhecido: {args.module}", file=sys.stderr)
        print("use: redteam list", file=sys.stderr)
        return 2

    ctx = _make_ctx(args)

    # Modulos que nao precisam de alvo (crypto/physical/ransomware) pulam a checagem
    if cls.meta.requires_target:
        try:
            ctx.check_target(cls.meta.name)
        except GuardrailError as e:
            print(f"[BLOQUEADO] {e}", file=sys.stderr)
            return 3

    run_id = ctx.storage.start_run(cls.meta.name, ctx.target, ctx.mode)
    ctx.run_id = run_id

    print(f"→ {cls.meta.name} em {ctx.target} (modo {ctx.mode})")
    try:
        mod = cls(ctx)
        findings = mod.run()
    except GuardrailError as e:
        ctx.storage.finish_run(run_id, ok=False)
        print(f"[BLOQUEADO] {e}", file=sys.stderr)
        return 3
    except Exception as e:
        ctx.storage.finish_run(run_id, ok=False)
        print(f"[ERRO] {type(e).__name__}: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 4

    for f in findings:
        ctx.storage.add_finding(run_id, f)
    ctx.storage.finish_run(run_id, ok=True)

    print(f"  {len(findings)} achado(s) registrado(s) (run #{run_id})")

    block = None
    if not args.no_llm and findings:
        print("  analisando com LLM...")
        block = llm_analysis(findings, ctx.target, prefer=args.llm)

    meta = {
        "run_id": run_id,
        "module": cls.meta.name,
        "mode": ctx.mode,
        "results": {k: v for k, v in ctx.results.items() if k != "attempts"},
    }
    md = render_markdown(findings, ctx.target, llm_block=block, meta=meta)
    js = render_json(findings, ctx.target, meta=meta) if args.json else None

    out = Path(args.out) if args.out else Path(f"relatorio-{cls.meta.name}-{run_id}.md")
    write_report(out, md, js)
    print(f"  relatorio: {out}")
    if args.json:
        print(f"  json: {out.with_suffix('.json')}")
    if block and block.get("resumo"):
        print("\n" + block["resumo"][:600])
    return 0


def cmd_report(args) -> int:
    st = Storage(args.db)
    rows = st.findings(args.run_id)
    if not rows:
        print(f"run #{args.run_id} sem achados", file=sys.stderr)
        return 1
    from .core.storage import Finding as F
    findings = [F(module=r["module"], severity=r["severity"], title=r["title"],
                  detail=r["detail"] or "", evidence=r["evidence"] or "",
                  mitre=r["mitre"] or "") for r in rows]
    runs = {r["id"]: r for r in st.runs()}
    target = runs.get(args.run_id, {}).get("target", "?")
    block = llm_analysis(findings, target, prefer=args.llm)
    md = render_markdown(findings, target, llm_block=block,
                         meta={"run_id": args.run_id})
    write_report(Path(args.out), md)
    print(f"relatorio: {args.out}")
    return 0


def cmd_llm(args) -> int:
    """Mostra qual adaptador sera usado e, com --ping, testa a chamada."""
    from .core.llm import (AnthropicClient, OfflineClient, OpenAICompatClient,
                           get_client, redact)

    c = get_client(args.provider)
    nome = type(c).__name__
    print(f"  provedor : {args.provider}")
    print(f"  adapter  : {nome}")
    print(f"  modelo   : {c.model}")

    if isinstance(c, OpenAICompatClient):
        print(f"  base_url : {c.base_url}")
        print(f"  api_key  : {'configurada' if c.available() else 'AUSENTE'}")
    elif isinstance(c, AnthropicClient):
        print(f"  base_url : {c.base_url or '(default anthropic)'}")
        print(f"  api_key  : {'configurada' if c.available() else 'AUSENTE'}")
    else:
        print("  modo     : offline (heuristica local, sem rede)")

    if not args.ping:
        print("\n  dicas:")
        print("    export OPENROUTER_API_KEY=...   # OpenRouter (default)")
        print("    export ANTHROPIC_API_KEY=...    # Claude via SDK anthropic")
        print("    redteam llm --ping              # testa a chamada")
        return 0

    print("\n  enviando chamada de teste...")
    resp = c.complete(
        "Responda sempre em portugues do Brasil.",
        '{"target":"127.0.0.1","findings":[]}',
        timeout=30.0,
    )
    print("  resposta:")
    print("    " + redact(resp).replace("\n", "\n    ")[:800])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner:
        use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        print_banner(color=use_color)

    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "dashboard":
        from .core.dashboard import serve
        serve(args.db, host=args.host, port=args.port)
        return 0
    if args.cmd == "llm":
        return cmd_llm(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
