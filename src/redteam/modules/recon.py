"""Recon de rede: varredura TCP concorrente + banner grabbing + fingerprint leve.

Funcional de verdade (abre sockets, le banners), mas so contra alvos
permitidos pela TargetPolicy. Nenhuma exploração: apenas descoberta.
MITRE: T1595 (Active Scanning), T1046 (Network Service Discovery).
"""

from __future__ import annotations

import concurrent.futures as cf
import socket
import ssl
from dataclasses import dataclass
from typing import Iterable, Optional

from ..core.mitre import TECHNIQUES  # noqa: F401  (documenta o mapa)
from ..core.registry import BaseModule, ModuleMeta, register
from ..core.storage import Finding

# Serviços comuns -> risco percebido (usado no relatorio)
KNOWN = {
    21: ("ftp", "medium"),
    22: ("ssh", "low"),
    23: ("telnet", "high"),
    25: ("smtp", "low"),
    53: ("dns", "low"),
    80: ("http", "low"),
    110: ("pop3", "medium"),
    143: ("imap", "medium"),
    443: ("https", "low"),
    445: ("smb", "high"),
    1433: ("mssql", "high"),
    1521: ("oracle", "high"),
    2049: ("nfs", "high"),
    3306: ("mysql", "high"),
    3389: ("rdp", "high"),
    5432: ("postgres", "high"),
    5900: ("vnc", "high"),
    6379: ("redis", "critical"),
    9200: ("elasticsearch", "critical"),
    11211: ("memcached", "critical"),
    27017: ("mongodb", "critical"),
}


@dataclass
class ScanResult:
    port: int
    open: bool
    banner: str = ""
    service: str = ""
    tls_subject: str = ""

    def as_dict(self) -> dict:
        return {
            "port": self.port,
            "open": self.open,
            "banner": self.banner,
            "service": self.service,
            "tls_subject": self.tls_subject,
        }


def _grab(host: str, port: int, timeout: float) -> str:
    """Le um banner generico (HTTP HEAD, ou qualquer bytes iniciais)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            try:
                data = s.recv(1024)
            except socket.timeout:
                return ""
            return data.decode("utf-8", "replace").strip()[:300]
    except OSError:
        return ""


def _tls_subject(host: str, port: int, timeout: float) -> str:
    if port not in (443, 8443, 993, 995):
        return ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                subj = cert.get("subject", ())
                if subj:
                    return str(subj[0])
    except Exception:
        return ""
    return ""


def scan_port(host: str, port: int, timeout: float = 0.6) -> ScanResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service, _ = KNOWN.get(port, ("", "info"))
            return ScanResult(
                port=port,
                open=True,
                banner=_grab(host, port, timeout),
                service=service,
                tls_subject=_tls_subject(host, port, timeout),
            )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ScanResult(port=port, open=False)


def parse_ports(spec: str) -> list[int]:
    """'80,443,8000-8010' -> lista de ints."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def scan_host(
    host: str, ports: Iterable[int], workers: int = 64, timeout: float = 0.6
) -> list[ScanResult]:
    results: list[ScanResult] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in cf.as_completed(futs):
            results.append(fut.result())
    return sorted(results, key=lambda r: r.port)


@register
class ReconModule(BaseModule):
    meta = ModuleMeta(
        name="recon",
        description="Varredura TCP + banner grabbing + fingerprint de servico",
        category="recon",
        mitre=["T1595", "T1046", "T1592"],
        destructive=False,
    )

    def run(self) -> list[Finding]:
        target = self.ctx.target
        ports = parse_ports(self.ctx.options.get("ports", "1-1024"))
        timeout = float(self.ctx.options.get("timeout", 0.6))
        workers = int(self.ctx.options.get("workers", 64))

        self.ctx.log(f"varredura em {target} ({len(ports)} portas)")
        results = scan_host(target, ports, workers=workers, timeout=timeout)
        self.ctx.results["ports"] = [r.as_dict() for r in results]

        findings: list[Finding] = []
        for r in results:
            if not r.open:
                continue
            service, sev = KNOWN.get(r.port, ("desconhecido", "info"))
            ev = f"{target}:{r.port}"
            if r.banner:
                ev += f" banner={r.banner[:120]!r}"
            findings.append(
                Finding(
                    module="recon",
                    severity=sev,
                    title=f"Porta {r.port} aberta ({service})",
                    detail=(
                        f"Servico identificado: {service}. "
                        f"Exposicao desnecessaria aumenta superficie de ataque."
                    ),
                    evidence=ev,
                    mitre="T1046",
                )
            )
            if r.tls_subject:
                findings.append(
                    Finding(
                        module="recon",
                        severity="info",
                        title=f"TLS em {r.port}: {r.tls_subject[:80]}",
                        detail="Certificado coletado para inventario.",
                        evidence=r.tls_subject[:200],
                        mitre="T1592",
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    module="recon",
                    severity="info",
                    title="Nenhuma porta aberta no intervalo",
                    detail=f"{len(ports)} portas verificadas em {target}.",
                    evidence=f"{target} sem portas abertas",
                    mitre="T1046",
                )
            )
        return findings
