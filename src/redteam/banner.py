"""Banner ASCII redteam-cli — estilo BlackArch (vermelho/preto).

Mantido aqui (e nao gerado em runtime) para o projeto nao depender de pyfiglet.
"""

LOGO = r"""
 ██▀███  ▓█████ ▓█████▄ ▄▄▄█████▓▓█████ ▄▄▄       ███▄ ▄███▓
▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓  ██▒ ▓▒▓█   ▀▒████▄    ▓██▒▀█▀ ██▒
▓██ ░▄█ ▒▒███   ░██   █▌▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▓██    ▓██░
▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒██    ▒██ 
░██▓ ▒██▒░▒████▒░▒████▓   ▒██▒ ░ ░▒████▒▓█   ▓██▒▒██▒   ░██▒
░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒   ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ▒░   ░  ░
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒     ░     ░ ░  ░ ▒   ▒▒ ░░  ░      ░
  ░░   ░    ░    ░ ░  ░   ░         ░    ░   ▒   ░      ░   
   ░        ░  ░   ░                ░  ░     ░  ░       ░   
                 ░
"""

TAGLINE = "  recon · web · credenciais · cripto · ransomware · físico"
WARNING = "  ⚠  uso autorizado apenas — alvo de laboratório"


RESET = "\033[0m"
RED = "\033[38;5;196m"      # vermelho agressivo (BlackArch)
DRED = "\033[38;5;124m"     # vermelho escuro
GREY = "\033[38;5;240m"     # cinza estrutural
WHITE = "\033[38;5;255m"


def print_banner(color: bool = True) -> None:
    """Imprime o banner. Vermelho/preto por padrao (tema BlackArch)."""
    logo = f"{RED}{LOGO}{RESET}" if color else LOGO
    tag = f"{WHITE}{TAGLINE}{RESET}" if color else TAGLINE
    warn = f"{DRED}{WARNING}{RESET}" if color else WARNING
    print(logo)
    print(tag)
    print(warn)
    print()


BANNER = LOGO
