import sys

import pytest

sys.path.insert(0, "src")

from redteam.core.dashboard import load, render  # noqa: E402
from redteam.core.storage import Finding, Storage  # noqa: E402


def _seed(tmp_path):
    st = Storage(tmp_path / "t.db")
    rid = st.start_run("recon", "127.0.0.1", "sim")
    st.add_finding(rid, Finding(module="recon", severity="critical", title="porta 6379",
                                detail="redis exposto", mitre="T1046"))
    st.add_finding(rid, Finding(module="recon", severity="low", title="porta 80"))
    st.finish_run(rid, ok=True)
    st.close()
    return tmp_path / "t.db"


def test_load_vazio_quando_db_nao_existe(tmp_path):
    d = load(str(tmp_path / "nope.db"))
    assert d["findings"] == [] and d["runs"] == []


def test_load_conta_por_severidade(tmp_path):
    d = load(str(_seed(tmp_path)))
    assert d["counts"] == {"critical": 1, "low": 1}
    assert len(d["runs"]) == 1


def test_render_mostra_severidades_e_total(tmp_path):
    html = render(load(str(_seed(tmp_path))))
    assert "critical" in html
    assert "porta 6379" in html
    assert "T1046" in html
    assert ">2<" in html  # card de total


def test_render_escapa_html(tmp_path):
    st = Storage(tmp_path / "x.db")
    rid = st.start_run("sqli", "127.0.0.1", "sim")
    st.add_finding(rid, Finding(module="sqli", severity="high",
                                title="<script>alert(1)</script>"))
    st.finish_run(rid)
    st.close()
    html = render(load(str(tmp_path / "x.db")))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_sem_achados(tmp_path):
    html = render({"runs": [], "findings": [], "counts": {}, "db": "x.db"})
    assert "nenhum achado" in html
