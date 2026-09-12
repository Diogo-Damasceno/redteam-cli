import pytest

from redteam.core.guardrails import GuardrailError, Sandbox, TargetPolicy
from redteam.core.mitre import describe
from redteam.core.storage import Finding, Storage, findings_by_severity


def test_target_policy_bloqueia_publico():
    p = TargetPolicy(lab_only=True)
    ok, _ = p.allows("8.8.8.8")
    assert ok is False


def test_target_policy_permite_loopback():
    p = TargetPolicy(lab_only=True)
    ok, reason = p.allows("127.0.0.1")
    assert ok is True
    assert reason == "lab-range"


def test_allowlist_libera_host_fora_do_lab():
    p = TargetPolicy(allowlist={"meu.host"}, lab_only=True)
    # nao resolvivel, mas esta na allowlist -> passa
    ok, reason = p.allows("meu.host")
    assert ok is True
    assert reason == "allowlist"


def test_sandbox_bloqueia_traversal(tmp_path):
    s = Sandbox(tmp_path / "box")
    with pytest.raises(GuardrailError):
        s.resolve("../../etc/passwd")


def test_sandbox_resolve_dentro(tmp_path):
    s = Sandbox(tmp_path / "box")
    p = s.resolve("a/b.txt")
    assert str(p).startswith(str(s.root))


def test_storage_roundtrip():
    st = Storage(":memory:")
    rid = st.start_run("recon", "127.0.0.1", "sim")
    st.add_finding(rid, Finding(module="recon", severity="high", title="porta 22"))
    st.finish_run(rid, ok=True)
    rows = st.findings(rid)
    assert len(rows) == 1
    assert rows[0]["title"] == "porta 22"
    assert st.runs()[0]["id"] == rid


def test_findings_by_severity():
    rows = [
        {"severity": "high"}, {"severity": "high"}, {"severity": "low"},
    ]
    assert findings_by_severity(rows) == {"high": 2, "low": 1}


def test_mitre_describe():
    assert "T1046" in describe("T1046")
    assert "nao mapeado" in describe("T9999")
