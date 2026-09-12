"""Configuracao de testes do redteam-cli.

Aplica o tema BlackArch (vermelho/preto, azul somente em PASSED) e imprime
o banner do projeto no cabecalho da sessao do pytest.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import blackarch_theme  # noqa: E402
from blackarch_theme import banner_lines  # noqa: E402

try:
    from redteam.banner import LOGO, TAGLINE, WARNING

    _BANNER = LOGO + "\n" + TAGLINE + "\n" + WARNING
except Exception:  # pragma: no cover - fallback se o src nao estiver no path
    _BANNER = "REDTEAM-CLI"


blackarch_theme.install()


def pytest_report_header(config):
    return banner_lines(_BANNER)
