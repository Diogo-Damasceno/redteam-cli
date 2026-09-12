"""Auditoria de material criptografico + cracking offline (wordlist/mask).

Duas metades, ambas FUNCIONAIS:
  * AUDITORIA: le um arquivo de hashes e aponta ALGORITMO FRACO (MD5/SHA1 sem
    salt), senhas em arquivos de config, chaves privadas expostas.
  * CRACKING OFFLINE: itera wordlist com variantes e reporta o que quebrou
    — 100% local, sem rede.

Nada de quebrar TLS nem downgrade: o modulo ANALISA e PROVA FORCA em dados
que o operador possui.

MITRE: T1110 (Brute Force), T1552.001 (Credentials In Files),
T1600 (Weaken Encryption — no sentido de IDENTIFICAR configuracao fraca).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

WEAK_HASH_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
WEAK_ALGOS = {"MD5": "high", "SHA-1": "high", "SHA-256": "medium"}

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "admin", "welcome",
    "senha", "brasil", "1234567890", "suporte", "teste", "root",
]

SECRET_PATTERNS = [
    (r"(?i)password\s*[=:]\s*\S+", "senha em claro"),
    (r"(?i)api[_-]?key\s*[=:]\s*\S+", "api key em claro"),
    (r"(?i)secret\s*[=:]\s*\S+", "secret em claro"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "chave privada"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*\S+", "credencial AWS"),
]


def hash_of(algo: str, text: str, salt: str = "") -> str:
    data = (salt + text).encode() if salt else text.encode()
    return hashlib.new(algo, data).hexdigest()


def _variants(word: str) -> list[str]:
    out = {word, word.lower(), word.upper(), word.capitalize()}
    for suf in ("", "1", "12", "123", "!", "2024", "2025", "2026"):
        out.add(word + suf)
    return [v for v in out if v]


def crack_hash(digest: str, wordlist: list[str], algo: str = "md5",
               salt: str = "") -> str | None:
    """Tenta quebrar UM hash contra a wordlist (com variantes)."""
    for w in wordlist:
        for cand in _variants(w):
            if hmac.compare_digest(hash_of(algo, cand, salt), digest.lower()):
                return cand
    return None


def guess_algo(digest: str) -> str | None:
    return WEAK_HASH_LEN.get(len(digest.strip()))


@register
class CryptoAuditModule(BaseModule):
    meta = ModuleMeta(
        name="crypto",
        description="Auditoria de hashes/senhas + cracking offline por wordlist",
        category="crypto",
        mitre=["T1110", "T1552.001", "T1600"],
        destructive=False,
        requires_target=False,
    )

    def run(self) -> list[Finding]:
        path = Path(self.ctx.options.get("path", self.ctx.target or "."))
        algo = self.ctx.options.get("algo", "md5")
        salt = self.ctx.options.get("salt", "")
        wordlist = self.ctx.options.get("wordlist") or COMMON_PASSWORDS
        do_crack = bool(self.ctx.options.get("crack"))

        if not path.exists():
            return [Finding(
                module="crypto", severity="info",
                title="Arquivo/diretorio nao encontrado",
                detail=f"{path} nao existe.", evidence=str(path), mitre="T1552.001",
            )]

        files = [path] if path.is_file() else [p for p in sorted(path.rglob("*")) if p.is_file()]
        findings: list[Finding] = []
        scanned = 0

        # 1) segredos em arquivos
        for p in files:
            if p.stat().st_size > 2_000_000:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for pat, label in SECRET_PATTERNS:
                m = re.search(pat, text)
                if m:
                    findings.append(Finding(
                        module="crypto", severity="high",
                        title=f"{label} em {p.name}",
                        detail="Segredo exposto. Rotacione e mova para cofre/env var.",
                        evidence=f"{p}:{m.group(0)[:80]}",
                        mitre="T1552.001",
                    ))

        # 2) hashes fracos
        weak = 0
        for p in files[:200]:
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    guess = guess_algo(line)
                    if guess and guess in WEAK_ALGOS:
                        weak += 1
                        if weak <= 5:
                            findings.append(Finding(
                                module="crypto", severity=WEAK_ALGOS[guess],
                                title=f"Hash {guess} sem salt detectado",
                                detail=(
                                    f"{guess} (sem salt/KDF) e quebravel em massa. "
                                    "Use bcrypt/scrypt/Argon2id."
                                ),
                                evidence=f"{p.name}: {line[:24]}...",
                                mitre="T1600",
                            ))
            except OSError:
                continue

        if weak:
            findings.append(Finding(
                module="crypto", severity="high",
                title=f"{weak} hashes fracos (MD5/SHA-1) no total",
                detail="Substitua por KDF com salt e custo (Argon2id/bcrypt).",
                evidence=f"{weak} ocorrencias", mitre="T1600",
            ))

        # 3) cracking offline
        if do_crack:
            digests: list[tuple[str, str]] = []
            for p in files[:200]:
                try:
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if guess_algo(line):
                            digests.append((line, p.name))
                except OSError:
                    continue
            cracked = []
            for digest, src in digests[:500]:
                got = crack_hash(digest, wordlist, algo=algo, salt=salt)
                if got:
                    cracked.append({"hash": digest[:16] + "...", "plain": got, "source": src})
            self.ctx.results["cracked"] = cracked
            for c in cracked[:10]:
                findings.append(Finding(
                    module="crypto", severity="critical",
                    title=f"Hash quebrado: '{c['plain']}'",
                    detail=f"Recuperado por wordlist em {c['source']}.",
                    evidence=str(c), mitre="T1110",
                ))
            if not cracked:
                findings.append(Finding(
                    module="crypto", severity="info",
                    title=f"Nenhum hash quebrado ({len(digests)} testados)",
                    detail="Aumente a wordlist (--wordlist arquivo.txt).",
                    evidence=f"{len(digests)} hashes", mitre="T1110",
                ))

        if not findings:
            findings.append(Finding(
                module="crypto", severity="info",
                title="Nenhum achado criptografico",
                detail=f"{scanned} arquivos verificados.",
                evidence=str(path), mitre="T1552.001",
            ))
        return findings
