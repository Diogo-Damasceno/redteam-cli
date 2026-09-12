"""Sondagem de SQL Injection com DETECCAO POR COMPORTAMENTO (sem destruicao).

Estrategia: injeta payloads que provocam diferenca OBSERVAVEL (erro do SGBD,
mudanca de status HTTP, atraso) e nunca DELETE/DROP/UPDATE. O objetivo e
provar a vulnerabilidade, nao extrair ou corromper dados.

MITRE: T1190 (Exploit Public-Facing Application).
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

# Sondas inofensivas: provocam erro/alteracao de logica, NAO destruicao.
PROBES = [
    ("quote", "'"),
    ("double_quote", '"'),
    ("boolean_true", "' OR '1'='1"),
    ("boolean_false", "' OR '1'='2"),
    ("semicolon", "';--"),
    ("paren", "')--"),
]

DB_ERRORS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_", "MySQL"),
    (r"unclosed quotation mark", "MSSQL"),
    (r"Microsoft OLE DB", "MSSQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"sqlite3?\.OperationalError", "SQLite"),
    (r"ORA-\d{5}", "Oracle"),
    (r"SQLSTATE\[", "PDO/PHP"),
]


def _get(url: str, timeout: float, headers: dict | None = None) -> tuple[int, str, float]:
    req = urllib.request.Request(url, headers=headers or {})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:  # timeout, dns, conn reset
        return 0, str(e), time.time() - t0


def _detect_db_error(body: str) -> str | None:
    for pat, name in DB_ERRORS:
        if re.search(pat, body, re.I):
            return name
    return None


def build_url(base: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(base)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    replaced = [(k, value if k == param else v) for k, v in qs]
    if not any(k == param for k, _ in qs):
        replaced.append((param, value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(replaced), parts.fragment)
    )


@register
class SqliProbeModule(BaseModule):
    meta = ModuleMeta(
        name="sqli",
        description="Sondagem de SQL Injection por comportamento (nao destrutiva)",
        category="web",
        mitre=["T1190"],
        destructive=False,
    )

    def run(self) -> list[Finding]:
        target = self.ctx.target  # ex: http://127.0.0.1:8080/search?q=1
        param = self.ctx.options.get("param", "")
        timeout = float(self.ctx.options.get("timeout", 5))
        findings: list[Finding] = []

        if not param:
            return [Finding(
                module="sqli", severity="info",
                title="Parametro nao informado",
                detail="Use --param <nome> para indicar qual parametro sondar.",
                evidence=target, mitre="T1190",
            )]

        base_status, base_body, base_time = _get(target, timeout)
        if base_status == 0:
            return [Finding(
                module="sqli", severity="info",
                title="Alvo inacessivel",
                detail=f"Falha ao alcancar {target}: {base_body[:120]}",
                evidence=base_body[:200], mitre="T1190",
            )]

        self.ctx.results["baseline"] = {
            "status": base_status, "len": len(base_body), "time": round(base_time, 3)
        }

        for label, payload in PROBES:
            url = build_url(target, param, payload)
            status, body, elapsed = _get(url, timeout)
            self.ctx.log(f"probe {label} -> status={status} len={len(body)}")

            db = _detect_db_error(body)
            if db:
                findings.append(Finding(
                    module="sqli", severity="critical",
                    title=f"SQL Injection (erro de {db}) via '{param}'",
                    detail=(
                        f"O payload {payload!r} provocou erro do SGBD {db}, "
                        "indicando concatenacao de entrada na query."
                    ),
                    evidence=f"{url} :: {body[:200]}",
                    mitre="T1190",
                ))
                break

            # Diferenca de conteudo entre TRUE e FALSE (boolean-based)
            if status != base_status and status != 0:
                findings.append(Finding(
                    module="sqli", severity="medium",
                    title=f"Comportamento alterado ({label}) em '{param}'",
                    detail=f"Status mudou de {base_status} para {status}.",
                    evidence=f"{url} :: status={status}",
                    mitre="T1190",
                ))

        # Atraso anormal (heuristica fraca: pode ser rede)
        if base_time > 0 and elapsed > max(4.0, base_time * 5):
            findings.append(Finding(
                module="sqli", severity="low",
                title=f"Possivel time-based blind em '{param}'",
                detail=f"Resposta levou {elapsed:.1f}s vs baseline {base_time:.1f}s.",
                evidence=f"{target} :: {elapsed:.1f}s",
                mitre="T1190",
            ))

        if not findings:
            findings.append(Finding(
                module="sqli", severity="info",
                title="Nenhum indicio de SQLi no parametro testado",
                detail=f"{len(PROBES)} sondas aplicadas em '{param}' sem divergencia.",
                evidence=target, mitre="T1190",
            ))
        return findings
