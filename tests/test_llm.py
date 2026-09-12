"""Testes do adaptador de LLM (redteam-cli).

Nenhum teste faz chamada de rede: os SDKs sao substituidos por monkeypatch
ou a chave e removida do ambiente para forcar o fallback offline.
"""

import json
import sys

import pytest

sys.path.insert(0, "src")

from redteam.core import llm  # noqa: E402


@pytest.fixture(autouse=True)
def _env_limpo(monkeypatch):
    """Garante que nenhuma chave real do ambiente vaze para os testes."""
    for v in ("REDTEAM_LLM_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY",
              "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "REDTEAM_LLM_BASE_URL",
              "REDTEAM_LLM_MODEL", "ANTHROPIC_MODEL", "LLM_API_BASE"):
        monkeypatch.delenv(v, raising=False)


def test_redact_corta_segredo():
    txt = "api_key=SUPERSEGREDO123 outras coisas"
    out = llm.redact(txt)
    assert "SUPERSEGREDO123" not in out
    assert "[REDACTED]" in out


def test_redact_preserva_texto_normal():
    txt = "porta 22 aberta no host 127.0.0.1"
    assert llm.redact(txt) == txt


def test_offline_client_devolve_bloco_valido():
    c = llm.OfflineClient()
    payload = json.dumps({"findings": [
        {"severity": "critical", "title": "redis exposto", "detail": "sem senha"},
        {"severity": "low", "title": "banner", "detail": "nginx"},
    ]})
    out = json.loads(c.complete(llm.SYSTEM_PROMPT, payload))
    assert set(out) == {"resumo", "prioridades", "proximos_passos"}
    assert len(out["prioridades"]) == 2
    # critico primeiro
    assert out["prioridades"][0]["severidade"] == "critical"


def test_offline_client_sobrevive_a_json_invalido():
    c = llm.OfflineClient()
    out = json.loads(c.complete(llm.SYSTEM_PROMPT, "nao é json"))
    assert out["prioridades"] == []


def test_get_client_offline_quando_sem_chave():
    assert isinstance(llm.get_client("offline"), llm.OfflineClient)
    # auto sem nenhuma chave no ambiente -> tambem offline
    assert isinstance(llm.get_client("auto"), llm.OfflineClient)


def test_openai_client_disponivel_com_chave(monkeypatch):
    monkeypatch.setenv("REDTEAM_LLM_API_KEY", "sk-teste")
    c = llm.OpenAICompatClient()
    assert c.available() is True
    assert c.base_url == "https://openrouter.ai/api/v1"
    assert c.model == "openai/gpt-4o-mini"


def test_openai_client_respeita_env_custom(monkeypatch):
    monkeypatch.setenv("REDTEAM_LLM_API_KEY", "sk-teste")
    monkeypatch.setenv("REDTEAM_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("REDTEAM_LLM_MODEL", "llama3")
    c = llm.OpenAICompatClient()
    assert c.base_url == "http://localhost:11434/v1"
    assert c.model == "llama3"


def test_anthropic_client_disponivel_com_chave(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-teste")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
    c = llm.AnthropicClient()
    assert c.available() is True
    assert c.model == "claude-sonnet-4-5"


def test_get_client_auto_prefere_anthropic_quando_configurado(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-teste")
    c = llm.get_client("auto")
    assert isinstance(c, llm.AnthropicClient)


def test_get_client_auto_cai_para_openai_quando_so_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-teste")
    c = llm.get_client("auto")
    assert isinstance(c, llm.OpenAICompatClient)


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


def test_openai_client_chama_sdk_e_devolve_conteudo(monkeypatch):
    """Monkeypatch do SDK openai: prova o caminho feliz sem rede."""
    chamadas = {}

    class FakeCompletions:
        def create(self, **kw):
            chamadas.update(kw)
            return _Resp('{"resumo": "ok", "prioridades": [], "proximos_passos": []}')

    class FakeChat:
        def __init__(self):
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kw):
            chamadas["init"] = kw

        @property
        def chat(self):
            return FakeChat()

    import types

    fake = types.ModuleType("openai")
    fake.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)

    c = llm.OpenAICompatClient(api_key="sk-teste", model="x/y")
    out = c.complete("sys", '{"findings":[]}')
    assert json.loads(out)["resumo"] == "ok"
    assert chamadas["model"] == "x/y"
    assert chamadas["messages"][0]["role"] == "system"
    # a chave tem que chegar ao cliente
    assert chamadas["init"]["api_key"] == "sk-teste"


def test_openai_client_redact_antes_de_enviar(monkeypatch):
    """O payload do usuario nao pode conter segredo em claro."""
    enviado = {}

    class FakeCompletions:
        def create(self, **kw):
            enviado.update(kw)
            return _Resp("{}")

    class FakeChat:
        def __init__(self):
            self.completions = FakeCompletions()

    class FakeOpenAI:
        def __init__(self, **kw):
            pass

        @property
        def chat(self):
            return FakeChat()

    import types

    fake = types.ModuleType("openai")
    fake.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)

    c = llm.OpenAICompatClient(api_key="sk-teste")
    c.complete("sys", '{"findings":[{"detail":"password=hunter2"}]}')
    assert "hunter2" not in json.dumps(enviado)
    assert "[REDACTED]" in json.dumps(enviado)


def test_openai_client_falha_sem_quebrar(monkeypatch):
    """Erro de rede/SDK devolve JSON valido, nao excecao."""

    class FakeOpenAI:
        def __init__(self, **kw):
            pass

        @property
        def chat(self):
            raise RuntimeError("boom")

    import types

    fake = types.ModuleType("openai")
    fake.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)

    c = llm.OpenAICompatClient(api_key="sk-teste")
    out = json.loads(c.complete("sys", "{}"))
    assert "resumo" in out
    assert "falha" in out["resumo"] or "OFFLINE" in out["resumo"]


def test_build_prompt_enxuga_e_redact():
    findings = [
        {"module": "recon", "severity": "high", "title": "porta 22",
         # 50 repeticoes separadas por espaco: estoura o limite de 400 chars
         "detail": " ".join(["banner com senha: abc123 muito longo"] * 50),
         "mitre": "T1046"},
    ]
    out = json.loads(llm.build_prompt(findings, "127.0.0.1"))
    assert out["target"] == "127.0.0.1"
    f = out["findings"][0]
    assert set(f) == {"module", "severity", "title", "detail", "mitre"}
    assert "abc123" not in f["detail"]
    assert len(f["detail"]) <= 400


def test_redact_nao_altera_o_achado_local():
    """Fronteira de privacidade: redact protege o que VAI AO LLM.

    O achado guardado no banco e o relatorio local seguem intactos — o
    analista precisa ver a evidencia. So o prompt e sanitizado.
    """
    detalhe = "redis sem senha, senha: hunter2"
    assert llm.redact(detalhe) != detalhe
    assert "hunter2" not in llm.redact(detalhe)
    # o objeto original nao foi mutado
    assert detalhe == "redis sem senha, senha: hunter2"
