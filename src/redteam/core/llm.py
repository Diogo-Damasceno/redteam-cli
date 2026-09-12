"""Adaptadores de LLM — pluggable, igual ao fluxo que o Diogo ja usa.

O framework NUNCA depende de um provedor: `LLMClient` e uma interface,
`OpenAICompatClient` fala com qualquer endpoint OpenAI-compatible (OpenAI,
OpenRouter, Groq, LM Studio, vLLM...) via stdlib, e `OfflineClient`
degrada com elegancia (gera um relatorio heurístico sem rede).

Config: variaveis de ambiente
  REDTEAM_LLM_BASE_URL  ex: https://openrouter.ai/api/v1
  REDTEAM_LLM_API_KEY
  REDTEAM_LLM_MODEL     ex: deepseek/deepseek-r1

O adapter envia apenas os ACHADOS (sem segredos/credenciais em claro —
`redact()` corta valores sensiveis antes do prompt).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

SYSTEM_PROMPT = (
    "Voce e um analista de seguranca ofensiva senior escrevendo um relatorio "
    "de red team. Receba os achados em JSON e devolva, em portugues do Brasil, "
    "apenas um objeto JSON valido com as chaves: "
    "'resumo' (2-4 frases), 'prioridades' (lista de {titulo, severidade, "
    "racional, remediacao}), 'proximos_passos' (lista de strings). "
    "Nao invente achados. Seja tecnico e objective. "
    "Nunca inclua instrucoes de ataque a sistemas de terceiros."
)

SECRET_RE = re.compile(
    r"(?i)(password|passwd|senha|api[_-]?key|secret|token)\s*[=:]\s*\S+"
)


def redact(text: str) -> str:
    """Remove possiveis segredos antes de mandar ao LLM."""
    return SECRET_RE.sub(lambda m: m.group(0).split(m.group(0)[-1])[0] + "[REDACTED]", text)


@dataclass
class LLMClient:
    """Interface: todo adapter implementa `complete`."""

    model: str = "offline"

    def complete(self, system: str, user: str, timeout: float = 60.0) -> str:
        raise NotImplementedError

    def available(self) -> bool:
        return True


class OfflineClient(LLMClient):
    """Sem rede (ou sem chave): monta um JSON heurístico local."""

    def __init__(self):
        super().__init__(model="offline")

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, timeout: float = 60.0) -> str:
        try:
            data = json.loads(user)
            findings = data.get("findings", [])
        except Exception:
            findings = []
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 9))
        return json.dumps({
            "resumo": (
                f"{len(findings)} achados coletados. "
                f"Criticos: {sum(1 for f in findings if f.get('severity')=='critical')}, "
                f"altos: {sum(1 for f in findings if f.get('severity')=='high')}. "
                "Relatorio gerado OFFLINE (heuristica), sem analise de LLM."
            ),
            "prioridades": [
                {
                    "titulo": f.get("title", ""),
                    "severidade": f.get("severity", "info"),
                    "racional": f.get("detail", "")[:200],
                    "remediacao": "Revisar exposicao e aplicar hardening conforme o achado.",
                }
                for f in ranked[:10]
            ],
            "proximos_passos": [
                "Configurar REDTEAM_LLM_* para analise com LLM",
                "Fechar achados criticos/altos e re-executar o ciclo",
            ],
        }, ensure_ascii=False)


class OpenAICompatClient(LLMClient):
    """Qualquer endpoint OpenAI-compatible via urllib (stdlib)."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None):
        self.base_url = (base_url or os.getenv(
            "REDTEAM_LLM_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("REDTEAM_LLM_API_KEY", "")
        super().__init__(model=model or os.getenv("REDTEAM_LLM_MODEL", "openai/gpt-4o-mini"))

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, timeout: float = 60.0) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": redact(user)},
            ],
            "temperature": 0.2,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = json.loads(r.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError) as e:
            return json.dumps({
                "resumo": f"Falha na chamada ao LLM ({type(e).__name__}). "
                          "Caindo para analise offline na proxima execucao.",
                "prioridades": [],
                "proximos_passos": ["Verificar REDTEAM_LLM_BASE_URL/API_KEY/MODEL"],
            }, ensure_ascii=False)


def get_client(prefer: str = "auto") -> LLMClient:
    """auto = usa API se configurada, senao offline (nunca quebra o run)."""
    if prefer == "offline":
        return OfflineClient()
    c = OpenAICompatClient()
    if prefer == "api" or c.available():
        return c
    return OfflineClient()


def build_prompt(findings: Iterable[dict[str, Any]], target: str) -> str:
    slim = [
        {
            "module": f.get("module"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "detail": redact((f.get("detail") or "")[:400]),
            "mitre": f.get("mitre"),
        }
        for f in findings
    ]
    return json.dumps({"target": target, "findings": slim}, ensure_ascii=False)
