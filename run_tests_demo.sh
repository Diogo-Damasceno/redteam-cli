#!/usr/bin/env bash
# Testes ao vivo do redteam-cli — tema BlackArch (vermelho/preto, azul no PASSED).
# Roda em loop: salve qualquer arquivo e a suite re-roda sozinha.
cd "$(dirname "$0")" || exit 1
source .venv/bin/activate

INTERVAL="${INTERVAL:-2}"

run_once() {
    clear
    python -c "from redteam.banner import print_banner; print_banner()"
    python -m pytest tests/ -v --color=yes
    echo
    echo "  proxima execucao em ${INTERVAL}s  ·  Ctrl+C para sair"
}

if [ "${1:-}" = "--once" ]; then
    run_once
    exit $?
fi

while true; do
    run_once
    sleep "$INTERVAL"
done
