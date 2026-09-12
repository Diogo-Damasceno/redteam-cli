"""Dashboard local dos achados: servidor HTTP + HTML gerado do SQLite.

Serve a mesma base (redteam.db) que a CLI grava, entao o fluxo e:
  redteam run <modulo> ...   ->  grava findings
  redteam dashboard          ->  http://127.0.0.1:8765

Nada de dependencia externa: stdlib + HTML/CSS/JS puros.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
CORES = {
    "critical": "#e5484d",
    "high": "#f76b15",
    "medium": "#f5d90a",
    "low": "#3e63dd",
    "info": "#8b8b8b",
}

HTML = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>redteam-cli · dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
         background:#0d1117; color:#c9d1d9; }
  header { padding:18px 24px; border-bottom:1px solid #21262d; background:#161b22;
           display:flex; align-items:baseline; gap:16px; flex-wrap:wrap; }
  h1 { margin:0; font-size:17px; color:#e6edf3; }
  .sub { color:#8b949e; font-size:12px; }
  main { padding:20px 24px 40px; max-width:1280px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:8px; }
  .card { background:#161b22; border:1px solid #21262d; border-radius:8px; padding:14px; }
  .card .n { font-size:26px; font-weight:600; }
  .card .l { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#8b949e; }
  .bar { display:flex; height:10px; border-radius:5px; overflow:hidden; margin:14px 0 22px; background:#21262d; }
  .bar div { height:100%; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:#8b949e;
       margin:26px 0 10px; border-bottom:1px solid #21262d; padding-bottom:6px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; color:#8b949e; font-weight:500; padding:7px 8px; border-bottom:1px solid #21262d; }
  td { padding:7px 8px; border-bottom:1px solid #161b22; vertical-align:top; }
  .sev { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px;
         font-weight:600; color:#0d1117; white-space:nowrap; }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
  .ev { color:#8b949e; word-break:break-all; }
  .empty { color:#8b949e; padding:22px 0; }
  .foot { margin-top:26px; color:#6e7681; font-size:11px; border-top:1px solid #21262d; padding-top:10px; }
  a { color:#58a6ff; }
</style>
</head>
<body>
<header>
  <h1>redteam-cli · dashboard</h1>
  <span class="sub">base: __DB__</span>
  <span class="sub">atualize para recarregar</span>
</header>
<main>
  <div class="cards">__CARDS__</div>
  <div class="bar">__BAR__</div>

  <h2>Execuções</h2>
  <table><thead><tr><th>#</th><th>Módulo</th><th>Alvo</th><th>Modo</th><th>Início</th><th>OK</th></tr></thead>
  <tbody>__RUNS__</tbody></table>

  <h2>Achados (__NFINDINGS__)</h2>
  <table><thead><tr><th>Severidade</th><th>Módulo</th><th>Título</th><th>Detalhe</th><th>MITRE</th></tr></thead>
  <tbody>__FINDINGS__</tbody></table>

  <div class="foot">
    Gerado localmente por redteam-cli. Todos os alvos são de laboratório ou
    explicitamente autorizados. Nenhum dado sai desta máquina.
  </div>
</main>
</body>
</html>
"""


def _esc(v) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def load(db_path: str) -> dict:
    p = Path(db_path)
    if not p.exists():
        return {"runs": [], "findings": [], "counts": {}, "db": db_path}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    runs = [dict(r) for r in conn.execute(
        "SELECT * FROM runs ORDER BY id DESC LIMIT 100")]
    findings = [dict(r) for r in conn.execute(
        "SELECT * FROM findings ORDER BY "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT 1000")]
    conn.close()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {"runs": runs, "findings": findings, "counts": counts, "db": db_path}


def render(data: dict) -> str:
    counts = data["counts"]
    total = sum(counts.values())

    cards = []
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        cards.append(
            f'<div class="card"><div class="n" style="color:{CORES[sev]}">{n}</div>'
            f'<div class="l">{sev}</div></div>')
    cards.append(f'<div class="card"><div class="n">{total}</div><div class="l">total</div></div>')
    cards.append(
        f'<div class="card"><div class="n">{len(data["runs"])}</div><div class="l">execuções</div></div>')

    bar = ""
    if total:
        bar = "".join(
            f'<div style="width:{counts.get(s,0)/total*100:.2f}%;background:{CORES[s]}" '
            f'title="{s}: {counts.get(s,0)}"></div>' for s in SEV_ORDER if counts.get(s))

    runs_html = "".join(
        f"<tr><td class='mono'>{r['id']}</td><td>{_esc(r['module'])}</td>"
        f"<td class='mono'>{_esc(r['target'])}</td><td>{_esc(r['mode'])}</td>"
        f"<td class='mono'>{_esc(r['started_at'])}</td>"
        f"<td>{'sim' if r['ok'] else 'não'}</td></tr>"
        for r in data["runs"]) or '<tr><td colspan="6" class="empty">nenhuma execução registrada</td></tr>'

    def row(f):
        sev = f["severity"]
        return (
            f"<tr><td><span class='sev' style='background:{CORES.get(sev,'#8b8b8b')}'>"
            f"{_esc(sev)}</span></td><td class='mono'>{_esc(f['module'])}</td>"
            f"<td>{_esc(f['title'])}</td>"
            f"<td class='ev'>{_esc((f['detail'] or '')[:160])}</td>"
            f"<td class='mono'>{_esc(f['mitre'] or '')}</td></tr>")

    findings_html = "".join(row(f) for f in data["findings"]) or \
        '<tr><td colspan="5" class="empty">nenhum achado</td></tr>'

    return (HTML
            .replace("__DB__", _esc(data["db"]))
            .replace("__CARDS__", "".join(cards))
            .replace("__BAR__", bar)
            .replace("__RUNS__", runs_html)
            .replace("__FINDINGS__", findings_html)
            .replace("__NFINDINGS__", str(total)))


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Sobe o dashboard. Bloqueia ate Ctrl+C."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, body: bytes, ctype: str = "text/html; charset=utf-8", code: int = 200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                self._send(render(load(db_path)).encode())
            elif u.path == "/api/findings.json":
                d = load(db_path)
                self._send(json.dumps({"counts": d["counts"],
                                       "findings": d["findings"],
                                       "runs": d["runs"]},
                                      ensure_ascii=False, default=str).encode(),
                           ctype="application/json; charset=utf-8")
            elif u.path == "/api/export.csv":
                d = load(db_path)
                import csv
                import io
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["id", "run_id", "module", "severity", "title", "detail", "mitre"])
                for f in d["findings"]:
                    w.writerow([f["id"], f["run_id"], f["module"], f["severity"],
                                f["title"], (f["detail"] or "").replace("\n", " "), f["mitre"]])
                self._send(buf.getvalue().encode(), ctype="text/csv; charset=utf-8")
            else:
                self._send(b"404", ctype="text/plain", code=404)

    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"dashboard em http://{host}:{port}  (base: {db_path})")
    print("Ctrl+C para encerrar")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nencerrando")
    finally:
        srv.server_close()
