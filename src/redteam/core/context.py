"""Contexto de execucao compartilhado por todos os modulos."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .guardrails import AuditLog, Sandbox, TargetPolicy
from .storage import Storage


@dataclass
class Ctx:
    target: str
    options: dict[str, Any] = field(default_factory=dict)
    mode: str = "sim"
    verbose: bool = False
    policy: TargetPolicy = field(default_factory=TargetPolicy)
    sandbox: Optional[Sandbox] = None
    storage: Storage = field(default_factory=lambda: Storage(":memory:"))
    audit: Optional[AuditLog] = None
    run_id: Optional[int] = None
    results: dict[str, Any] = field(default_factory=dict)

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"  · {msg}", file=sys.stderr, flush=True)

    def check_target(self, module_name: str) -> None:
        """Bloqueia execucao fora da politica. Modulo chama isso antes de agir."""
        ok, reason = self.policy.allows(self.target)
        if self.audit:
            self.audit.record(module_name, "check_target", self.target,
                              allowed=ok, reason=reason)
        if not ok:
            from .guardrails import GuardrailError
            raise GuardrailError(reason)

    def audit_action(self, module: str, action: str, **detail) -> None:
        if self.audit:
            self.audit.record(module, action, self.target, **detail)
