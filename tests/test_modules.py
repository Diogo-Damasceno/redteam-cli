import hashlib
import sys

import pytest

sys.path.insert(0, "src")

from redteam.modules.crypto_audit import crack_hash, guess_algo, hash_of  # noqa: E402
from redteam.modules.ransomware_sim import (  # noqa: E402
    decrypt_bytes,
    encrypt_bytes,
    shannon_entropy,
)
from redteam.modules.recon import parse_ports  # noqa: E402


def test_parse_ports_range_e_lista():
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("1-3") == [1, 2, 3]
    assert parse_ports("5,1-2") == [1, 2, 5]


def test_guess_algo_por_tamanho():
    assert guess_algo(hash_of("md5", "x")) == "MD5"
    assert guess_algo(hash_of("sha1", "x")) == "SHA-1"
    assert guess_algo("abc") is None


def test_crack_hash_encontra_senha_fraca():
    digest = hash_of("md5", "123456")
    assert crack_hash(digest, ["123456"], algo="md5") == "123456"


def test_crack_hash_falha_quando_nao_esta_na_lista():
    digest = hash_of("md5", "senha-improvavel-xyz")
    assert crack_hash(digest, ["123456", "password"], algo="md5") is None


def test_cripto_roundtrip_e_entropia():
    key = hashlib.sha256(b"chave-de-teste").digest()
    original = b"conteudo secreto " * 50
    blob = encrypt_bytes(key, original, aad=b"arquivo.txt")
    assert blob != original
    assert shannon_entropy(blob) > shannon_entropy(original) - 0.5
    assert decrypt_bytes(key, blob, aad=b"arquivo.txt") == original


def test_cripto_falha_com_chave_errada():
    key1 = hashlib.sha256(b"a").digest()
    key2 = hashlib.sha256(b"b").digest()
    blob = encrypt_bytes(key1, b"dados", aad=b"x")
    with pytest.raises(Exception):
        decrypt_bytes(key2, blob, aad=b"x")
