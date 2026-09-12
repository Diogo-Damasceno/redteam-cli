"""Banner ASCII do redteam-cli.

Uso:
    from redteam.banner import BANNER, print_banner
    print_banner()          # colorido (se o terminal suportar)
"""

RESET = "\033[0m"
RED = "\033[38;5;196m"
DIM = "\033[38;5;244m"
CYAN = "\033[38;5;81m"

LOGO = r"""
██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║
██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

 ██████╗██╗     ██╗
██╔════╝██║     ██║
██║     ██║     ██║
██║     ██║     ██║
╚██████╗███████╗██║
 ╚═════╝╚══════╝╚═╝
"""

TAGLINE = "  recon · web · credenciais · cripto · ransomware · físico"
WARNING = "  ⚠  uso autorizado apenas — alvo de laboratório"


def print_banner(color: bool = True) -> None:
    logo = LOGO
    if color:
        logo = f"{RED}{LOGO}{RESET}"
        tag = f"{CYAN}{TAGLINE}{RESET}"
        warn = f"{DIM}{WARNING}{RESET}"
    else:
        tag, warn = TAGLINE, WARNING
    print(logo)
    print(tag)
    print(warn)
    print()


BANNER = LOGO
