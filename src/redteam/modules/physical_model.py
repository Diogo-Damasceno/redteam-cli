"""Modelagem de ataques fisicos: gera o PLANO e o CHECKLIST de defesa.

Nao ha "exploit fisico" para executar de dentro de uma CLI. O que este
modulo faz e o que um red teamer de verdade entrega nessa frente: um
cenarios-map (vetor, pre-requisito, tempo, ruido) e, do lado azul, os
controles que impedem cada vetor.

MITRE: T1200 (Hardware Additions), T1098 (Account Manipulation).
"""

from __future__ import annotations

from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

VECTORS = [
    {
        "id": "badusb",
        "name": "BadUSB / HID injection",
        "mitre": "T1200",
        "prereq": "Acesso fisico a porta USB por ~10s",
        "tempo": "< 30s",
        "ruido": "baixo",
        "impacto": "Execucao de comandos como o usuario (shell, exfil, persistencia)",
        "defesa": [
            "Bloquear/disable USB mass storage + HID por politica (usbguard)",
            "Whitelist de VID/PID; porta USB fisicamente bloqueada em servidores",
            "Deteccao de novos dispositivos HID (udev -> alerta)",
        ],
    },
    {
        "id": "evilmaid",
        "name": "Evil Maid / boot tampering",
        "mitre": "T1542",
        "prereq": "Acesso fisico prolongado + maquina desligada",
        "tempo": "5-15 min",
        "ruido": "medio",
        "impacto": "Bootkit/persistencia abaixo do SO; sobrevive a reinstalacao",
        "defesa": [
            "Full disk encryption + Secure Boot com chaves proprias",
            "Medicao TPM (PCRs) e atestado remoto",
            "Selos fisicos / inventario de lacre no rack",
        ],
    },
    {
        "id": "shoulder",
        "name": "Shoulder surfing / credencial observada",
        "mitre": "T1078",
        "prereq": "Proximidade visual",
        "tempo": "segundos",
        "ruido": "nenhum",
        "impacto": "Reuso de senha/PIN",
        "defesa": [
            "Filtros de privacidade; politica de tela limpa",
            "MFA resistente a phishing (FIDO2/WebAuthn)",
        ],
    },
    {
        "id": "rfid",
        "name": "Clonagem RFID/NFC de crachas",
        "mitre": "T1200",
        "prereq": "Leitor NFC a ~5cm do cracha",
        "tempo": "< 5s",
        "ruido": "nenhum",
        "impacto": "Acesso fisico a areas restritas",
        "defesa": [
            "Crachas com autenticacao mutua (MIFARE DESFire, nao UID-only)",
            "Deteccao de clone via contador de sessao no backend",
            "Rotacao de chaves e log de leitores",
        ],
    },
    {
        "id": "dumpster",
        "name": "Dumpster diving / midia descartada",
        "mitre": "T1213",
        "prereq": "Acesso ao descarte",
        "tempo": "variavel",
        "ruido": "nenhum",
        "impacto": "Documentos, midias e credenciais recuperadas",
        "defesa": [
            "Trituracao certificada (DIN 66399)",
            "Sanitizacao de midia (NIST 800-88) antes do descarte",
        ],
    },
]


@register
class PhysicalModelModule(BaseModule):
    meta = ModuleMeta(
        name="physical",
        description="Modelagem de vetores fisicos + controles de defesa",
        category="physical",
        mitre=["T1200", "T1098"],
        destructive=False,
        requires_target=False,
    )

    def run(self) -> list[Finding]:
        self.ctx.results["vectors"] = [
            {k: v for k, v in vec.items() if k != "defesa"} for vec in VECTORS
        ]

        findings: list[Finding] = []
        for vec in VECTORS:
            findings.append(Finding(
                module="physical",
                severity="high" if vec["ruido"] == "nenhum" else "medium",
                title=f"Vetor fisico: {vec['name']}",
                detail=(
                    f"Pre-requisito: {vec['prereq']}. Tempo: {vec['tempo']}. "
                    f"Ruido: {vec['ruido']}. Impacto: {vec['impacto']}."
                ),
                evidence=f"{vec['id']} :: {vec['name']}",
                mitre=vec["mitre"],
            ))
            for d in vec["defesa"]:
                findings.append(Finding(
                    module="physical", severity="info",
                    title=f"Controle: {vec['name']}",
                    detail=d,
                    evidence=f"defesa::{vec['id']}",
                    mitre=vec["mitre"],
                ))
        return findings
