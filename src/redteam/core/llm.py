"""Adaptadores de LLM — SDKs oficiais (openai / anthropic).

O framework NAO depende de um provedor so. Tres adapters, mesma interface:

  OpenAICompatClient  -> SDK `openai` apontando para qualquer endpoint
                         OpenAI-compatible. Default: OpenRouter.
  AnthropicClient     -> SDK `anthropic` (Claude).
  OfflineClient       -> sem rede/sem chave: heuristica local, nunca quebra.

Config (variaveis de ambiente)
  OpenRouter (default):
    REDTEAM_LLM_BASE_URL   https://openrouter.ai/api/v1
    REDTEAM_LLM_API_KEY    (ou OPENROUTER_API_KEY)
    REDTEAM_LLM_MODEL      ex: deepseek/deepseek-r1, openai/gpt-4o-mini
  Anthropic:
    ANTHROPIC_API_KEY      (ou ANTHROPIC_AUTH_TOKEN)
    ANTHROPIC_MODEL        ex: claude-sonnet-4-5
    ANTHROPIC_BASE_URL     (opcional)

Privacidade: `redact()` corta valores que parecem segredo antes de qualquer
prompt sair do processo.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Iterable

SYSTEM_PROMPT = (
    "Voce e um analista de seguranca ofensiva senior escrevendo um relatorio "
    "de red team. Receba os achados em JSON e devolva, em portugues do Brasil, "
    "apenas um objeto JSON valido com as chaves: "
    "'resumo' (2-4 frases), 'prioridades' (lista de {titulo, severidade, "
    "racional, remediacao}), 'proximos_passos' (lista de strings). "
    "Nao invente achados. Seja tecnico e objetivo. "
    "Nunca inclua instrucoes de ataque a sistemas de terceiros."
)

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|senha|api[_-]?key|secret|token)\b(\s*[=:]\s*)\S+"
)

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openai/gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"

TIMEOUT = 60.0


def redact(text: str) -> str:
    """Substitui o VALOR de possiveis segredos por [REDACTED].

    Corta tudo depois do separador (= ou :), nao so o ultimo caractere:
    'api_key=SUPERSEGREDO123 resto' -> 'api_key=[REDACTED]'.
    """
    return SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)


def _offline_payload(findings: list[dict], motivo: str = "") -> dict:
    """Bloco heurístico local: nunca deixa o relatorio sem resumo."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 9))
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    resumo = (
        f"{len(findings)} achado(s) coletado(s). Criticos: {crit}, altos: {high}. "
        "Relatorio gerado OFFLINE (heuristica), sem analise de LLM."
    )
    if motivo:
        resumo += f" Motivo: {motivo}"
    return {
        "resumo": resumo,
        "prioridades": [
            {
                "titulo": f.get("title", ""),
                "severidade": f.get("severity", "info"),
                "racional": (f.get("detail") or "")[:200],
                "remediacao": "Revisar exposicao e aplicar hardening conforme o achado.",
            }
            for f in ranked[:10]
        ],
        "proximos_passos": [
            "Configurar REDTEAM_LLM_API_KEY (ou OPENROUTER_API_KEY / ANTHROPIC_API_KEY)",
            "Fechar achados criticos/altos e re-executar o ciclo",
        ],
    }


@dataclass
class LLMClient:
    """Interface: todo adapter implementa `complete` e `available`."""

    model: str = "offline"

    def complete(self, system: str, user: str, timeout: float = TIMEOUT) -> str:
        raise NotImplementedError

    def available(self) -> bool:
        return True


class OfflineClient(LLMClient):
    """Sem rede (ou sem chave): monta um JSON heuristico local."""

    def __init__(self, motivo: str = ""):
        self.motivo = motivo
        super().__init__(model="offline")

    def available(self) -> bool:
        return True

    def complete(self, system: str, user: str, timeout: float = TIMEOUT) -> str:
        try:
            data = json.loads(user)
            findings = data.get("findings", [])
        except Exception:
            findings = []
        return json.dumps(_offline_payload(findings, self.motivo), ensure_ascii=False)


class OpenAICompatClient(LLMClient):
    """SDK oficial `openai` contra qualquer endpoint OpenAI-compatible.

    OpenRouter por padrao. Tambem serve para Groq, LM Studio, vLLM, Ollama
    (modo compativel) — basta REDTEAM_LLM_BASE_URL.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None):
        self.base_url = (
            base_url
            or os.getenv("REDTEAM_LLM_BASE_URL")
            or os.getenv("LLM_API_BASE")
            or DEFAULT_BASE_URL
        ).rstrip("/")
        self.api_key = (
            api_key
            or os.getenv("REDTEAM_LLM_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        )
        super().__init__(
            model=model
            or os.getenv("REDTEAM_LLM_MODEL")
            or os.getenv("OPENROUTER_MODEL")
            or DEFAULT_MODEL
        )

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, timeout: float = TIMEOUT) -> str:
        if not self.available():
            return json.dumps(
                _offline_payload([], "sem REDTEAM_LLM_API_KEY configurada"),
                ensure_ascii=False,
            )
        try:
            from openai import OpenAI
        except ImportError:
            return json.dumps(
                _offline_payload([], "SDK openai nao instalado (pip install openai)"),
                ensure_ascii=False,
            )

        try:
            client = OpenAI(
                api_key=self.api_key, base_url=self.base_url, timeout=timeout
            )
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": redact(user)},
                ],
                temperature=0.2,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            return json.dumps(
                _offline_payload([], f"falha na chamada ({type(e).__name__})"),
                ensure_ascii=False,
            )


class AnthropicClient(LLMClient):
    """SDK oficial `anthropic` (Claude)."""

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 base_url: str | None = None):
        self.api_key = (
            api_key
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("ANTHROPIC_AUTH_TOKEN")
            or ""
        )
        self.base_url = base_url or os.getenv("ANTHROPIC_BASE_URL") or None
        super().__init__(
            model=model
            or os.getenv("ANTHROPIC_MODEL")
            or DEFAULT_ANTHROPIC_MODEL
        )

    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, user: str, timeout: float = TIMEOUT) -> str:
        if not self.available():
            return json.dumps(
                _offline_payload([], "sem ANTHROPIC_API_KEY configurada"),
                ensure_ascii=False,
            )
        try:
            from anthropic import Anthropic
        except ImportError:
            return json.dumps(
                _offline_payload([], "SDK anthropic nao instalado (pip install anthropic)"),
                ensure_ascii=False,
            )

        try:
            kwargs: dict[str, Any] = {"api_key": self.api_key, "timeout": timeout}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            resp = Anthropic(**kwargs).messages.create(
                model=self.model,
                max_tokens=2048,
                system=system,
                messages=[{"role": "user", "content": redact(user)}],
            )
            text = "".join(
                getattr(b, "text", "")
                for b in resp.content
                if getattr(b, "type", "") == "text"
            )
            return text
        except Exception as e:
            return json.dumps(
                _offline_payload([], f"falha na chamada ({type(e).__name__})"),
                ensure_ascii=False,
            )


def get_client(prefer: str = "auto") -> LLMClient:
    """auto = anthropic se configurado, senao openai-compat, senao offline.

    Nunca quebra o run: sem chave ou sem SDK, cai no OfflineClient.
    """
    if prefer == "offline":
        return OfflineClient()

    if prefer in ("auto", "anthropic", "claude"):
        a = AnthropicClient()
        if a.available():
            return a
        if prefer != "auto":
            return OfflineClient("ANTHROPIC_API_KEY ausente")

    if prefer in ("auto", "api", "openai", "openrouter"):
        o = OpenAICompatClient()
        if o.available():
            return o
        if prefer != "auto":
            return OfflineClient("nenhuma chave de LLM configurada")

    return OfflineClient()


def build_prompt(findings: Iterable[dict[str, Any]], target: str) -> str:
    slim = [
        {
            "module": f.get("module"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "detail": redact(f.get("detail") or "")[:400],
            "mitre": f.get("mitre"),
        }
        for f in findings
    ]
    return json.dumps({"target": target, "findings": slim}, ensure_ascii=False)
