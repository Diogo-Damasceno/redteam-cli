"""Mapa MITRE ATT&CK (subset usado pelos modulos) + utilitarios de relatorio.

Nao e o catalogo completo — so as tecnicas que os modulos deste repo
realmente exercitam, para que o relatorio cite IDs verdadeiros.
"""

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1200": {"name": "Hardware Additions", "tactic": "Initial Access"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1600": {"name": "Weaken Encryption", "tactic": "Defense Evasion"},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
}


def describe(tid: str) -> str:
    t = TECHNIQUES.get(tid)
    if not t:
        return f"{tid} (nao mapeado)"
    return f"{tid} — {t['name']} ({t['tactic']})"


def describe_many(ids: list[str]) -> list[str]:
    return [describe(i) for i in ids]


def tactic_of(tid: str) -> str:
    return TECHNIQUES.get(tid, {}).get("tactic", "—")
