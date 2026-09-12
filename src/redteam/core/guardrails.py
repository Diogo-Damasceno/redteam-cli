"""Guardrails: o que separa um framework de lab de uma ferramenta de abuso.

Tres camadas:
  1. TargetPolicy — decide SE um alvo pode ser tocado (allowlist / lab / confirmacao).
  2. Sandbox      — caminhos de filesystem que um modulo destrutivo pode escrever.
  3. Audit        — tudo que o framework faz fica registrado (forense do proprio lab).

Regra: um modulo NUNCA executa acao de rede/disco direto. Ele chama
`guardrails.check_target()` / `guardrails.sandbox_path()` e recebe permissao
ou uma excecao. Isso centraliza a decisao etica em UM lugar testavel.
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

LAB_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class GuardrailError(RuntimeError):
    """Alvo ou caminho fora da politica do lab."""


def is_lab_address(host: str) -> bool:
    """True se o host e loopback/RFC1918 (escopo de lab)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in LAB_NETWORKS)


def normalize_host(value: str) -> str:
    """Extrai o host de uma URL ('http://127.0.0.1:8080/x' -> '127.0.0.1').

    A politica compara ENDERECO, nao URL: sem isso qualquer alvo com
    esquema/porta cai no 'fora do escopo' mesmo sendo loopback.
    """
    v = (value or "").strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if "@" in v:  # user:pass@host
        v = v.rsplit("@", 1)[1]
    if v.startswith("["):  # IPv6 [::1]:8080
        return v[1:].split("]", 1)[0]
    if ":" in v:
        v = v.rsplit(":", 1)[0]
    return v


def _resolve(host: str) -> Optional[str]:
    import socket

    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


@dataclass
class TargetPolicy:
    """Politica de alcance. Magra de proposito: um lugar so pra decidir."""

    allowlist: set[str] = field(default_factory=set)
    lab_only: bool = True
    require_confirm: bool = True

    def allows(self, host: str) -> tuple[bool, str]:
        host_norm = normalize_host(host)
        if host in self.allowlist or host_norm in self.allowlist:
            return True, "allowlist"

        resolved = _resolve(host_norm)
        addr = resolved or host_norm
        if self.lab_only:
            if not is_lab_address(addr):
                return False, (
                    f"host '{host}' ({addr}) fora do escopo de lab "
                    "(loopback/RFC1918). Use --targets targets.txt ou --i-own-it."
                )
            return True, "lab-range"

        if not is_lab_address(addr):
            return False, "modo live exige allowlist explicita"
        return True, "lab-range"


class Sandbox:
    """Filesystem carcerario para modulos destrutivos (ex: ransomware sim)."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()

    def ensure(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        return self.root

    def resolve(self, relpath: str) -> Path:
        """Resolve um caminho DENTRO do sandbox; bloqueia traversal."""
        self.ensure()
        candidate = (self.root / relpath).resolve()
        if not str(candidate).startswith(str(self.root)):
            raise GuardrailError(f"path traversal bloqueado: {relpath!r}")
        return candidate

    def contains(self, path: Path | str) -> bool:
        try:
            p = Path(path).resolve()
            return str(p).startswith(str(self.root))
        except OSError:
            return False


class AuditLog:
    """Log append-only (JSONL) de todas as acoes do framework."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, module: str, action: str, target: str, **detail) -> dict:
        entry = {
            "ts": time.time(),
            "module": module,
            "action": action,
            "target": target,
            **detail,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def read(self) -> Iterable[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def default_allowlist_path() -> Path:
    return Path(os.getenv("REDTEAM_ALLOWLIST", "targets.txt"))


def load_allowlist(path: Optional[Path] = None) -> set[str]:
    """Le allowlist (1 host por linha, '#' comenta). Arquivo ausente = vazio."""
    p = Path(path) if path else default_allowlist_path()
    if not p.exists():
        return set()
    out: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out
