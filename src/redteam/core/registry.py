"""Registry de modulos: descoberta, metadados e execucao uniforme.

Todo modulo herda BaseModule e declara: name, description, mitre (tecnicas
ATT&CK), destructive (se aponta disco/estado) e run(ctx) -> list[Finding].
O registry e o unico ponto que a CLI consulta, entao adicionar modulo =
escrever a classe e registrar via entrypoint interno.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.storage import Finding


@dataclass
class ModuleMeta:
    name: str
    description: str
    category: str          # recon | credential | crypto | ransomware | physical | web | post
    mitre: list[str] = field(default_factory=list)
    destructive: bool = False
    requires_target: bool = True


class BaseModule:
    meta: ModuleMeta

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self) -> list[Finding]:
        raise NotImplementedError


_REGISTRY: dict[str, type[BaseModule]] = {}


def register(cls: type[BaseModule]) -> type[BaseModule]:
    if not hasattr(cls, "meta"):
        raise TypeError(f"{cls.__name__} sem ModuleMeta")
    _REGISTRY[cls.meta.name] = cls
    return cls


def get(name: str) -> Optional[type[BaseModule]]:
    return _REGISTRY.get(name)


def all_modules() -> dict[str, type[BaseModule]]:
    return dict(_REGISTRY)


def by_category() -> dict[str, list[type[BaseModule]]]:
    out: dict[str, list[type[BaseModule]]] = {}
    for cls in _REGISTRY.values():
        out.setdefault(cls.meta.category, []).append(cls)
    for v in out.values():
        v.sort(key=lambda c: c.meta.name)
    return out


def load_builtins() -> None:
    """Importa os modulos embutidos para popular o registry."""
    from ..modules import (  # noqa: F401
        crypto_audit,
        credential_stuffing,
        physical_model,
        ransomware_sim,
        recon,
        sqli_probe,
    )
