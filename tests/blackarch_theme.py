"""Tema BlackArch para o pytest: vermelho/preto, azul SOMENTE em PASSED.

Carregado por tests/conftest.py (de cada projeto) — nao precisa de flag na
linha de comando e nao altera nenhum assert.

Mecanica: envolve o TerminalWriter do reporter. Toda palavra de resultado
(PASSED/FAILED/...) que o pytest escreve passa por aqui e e substituida pela
tag do tema; o verde e remapeado para azul na tabela ANSI.
"""

from __future__ import annotations

import _pytest.terminal as _terminal

R = "\033[0m"
RED = "\033[38;5;196m"
GREY = "\033[38;5;240m"
WHITE = "\033[38;5;255m"
BRED = "\033[48;5;196m"
BBLUE = "\033[48;5;33m"
BBLACK = "\033[48;5;232m"

Tw = _terminal.TerminalWriter

# "green" deixa de existir como verde: vira azul (33) em toda a saida
_tw_table = dict(Tw._esctable)
_tw_table["green"] = 33
Tw._esctable = _tw_table

_ORIG_STATS = _terminal.TerminalReporter.build_summary_stats_line
_ORIG_MAIN = _terminal.TerminalReporter._get_main_color

# Tag por resultado: fundo cheio, estilo BlackArch
_TAG = {
    "PASSED": f"{BBLUE}{WHITE} PASS {R}",
    "FAILED": f"{BRED}{WHITE} FAIL {R}",
    "ERROR": f"{BRED}{WHITE} ERR  {R}",
    "SKIPPED": f"{BBLACK}{GREY} SKIP {R}",
    "XFAIL": f"{BBLACK}{GREY} XFAIL{R}",
    "XPASS": f"{BBLACK}{GREY} XPASS{R}",
}
_WORDS = set(_TAG)


class ThemedWriter:
    """Envolve o TerminalWriter: troca a palavra de resultado pela tag."""

    def __init__(self, tw):
        self._tw = tw

    def __getattr__(self, name):
        return getattr(self._tw, name)

    @property
    def fullwidth(self):
        return self._tw.fullwidth

    @fullwidth.setter
    def fullwidth(self, v):
        self._tw.fullwidth = v

    def write(self, msg, *, flush=False, **markup):
        s = str(msg).strip()
        if s in _WORDS:
            return self._tw.write(_TAG[s], flush=flush)
        return self._tw.write(msg, flush=flush, **markup)

    def line(self, s="", **markup):
        return self._tw.line(s, **markup)


def _build_summary_stats_line(self):
    """Resumo final: sucesso em azul, nunca verde."""
    parts, main_color = _ORIG_STATS(self)
    if main_color == "green":
        main_color = "blue"
    fixed = []
    for text, markup in parts:
        m = dict(markup)
        if m.pop("green", None):
            m["blue"] = True
        fixed.append((text, m))
    return fixed, main_color


def _get_main_color(self) -> tuple[str, list[str]]:
    main_color, known_types = _ORIG_MAIN(self)
    return ("blue" if main_color == "green" else main_color), known_types


def install() -> None:
    """Aplica o tema no reporter do pytest."""
    _terminal.TerminalReporter.build_summary_stats_line = _build_summary_stats_line
    _terminal.TerminalReporter._get_main_color = _get_main_color

    # envolve o writer assim que o reporter e construido
    _ORIG_INIT = _terminal.TerminalReporter.__init__

    def _init(self, *args, **kwargs):
        _ORIG_INIT(self, *args, **kwargs)
        tw = getattr(self, "_tw", None)
        if tw is not None and not isinstance(tw, ThemedWriter):
            self._tw = ThemedWriter(tw)

    _terminal.TerminalReporter.__init__ = _init


def banner_lines(banner: str) -> list[str]:
    """Linhas do banner ASCII coloridas de vermelho (pytest_report_header)."""
    return [f"{RED}{line}{R}" for line in banner.strip("\n").splitlines()]
