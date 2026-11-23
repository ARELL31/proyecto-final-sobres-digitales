"""Pruebas de la API web."""
import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gui import crear_app
from rsa_mod import cargar_privada_pem, cargar_publica_pem
from sobre_digital import ARCHIVOS_EJEMPLO, DIR_EJEMPLOS


@pytest.fixture(scope="module")
def cliente():
    return crear_app().test_client()


@pytest.fixture(scope="module")
def par(cliente):
    return cliente.post("/api/claves", data={"bits": "2048"}).get_json()


@pytest.fixture(scope="module")
def otro_par(cliente):
    return cliente.post("/api/claves", data={"bits": "2048"}).get_json()


def _f(datos: bytes, nombre: str):
    return (BytesIO(datos), nombre)


def _crear(cliente, datos, nombre, pem_publica):
    return cliente.post(
        "/api/crear",
        data={"archivo": _f(datos, nombre), "publica": _f(pem_publica.encode(), "public_key.pem")},
        content_type="multipart/form-data",
    )


def _abrir(cliente, sobre_bytes, pem_privada):
    return cliente.post(
        "/api/abrir",
        data={"sobre": _f(sobre_bytes, "x.sobre.json"), "privada": _f(pem_privada.encode(), "private_key.pem")},
        content_type="multipart/form-data",
    )


def test_index(cliente):
    resp = cliente.get("/")
    assert resp.status_code == 200
    assert "Sobre digital" in resp.get_data(as_text=True)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_claves(cliente, bits):
    resp = cliente.post("/api/claves", data={"bits": str(bits)})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j["bits"] == bits and isinstance(j["tiempo_ms"], int)
    assert cargar_privada_pem(j["privada_pem"].encode()).key_size == bits
    assert cargar_publica_pem(j["publica_pem"].encode()).key_size == bits


@pytest.mark.parametrize("bits", ["1024", "abc"])
def test_claves_bits_invalidos(cliente, bits):
    resp = cliente.post("/api/claves", data={"bits": bits})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


@pytest.mark.parametrize("nombre", ARCHIVOS_EJEMPLO)
def test_crear_y_abrir(cliente, par, nombre):
    original = (DIR_EJEMPLOS / nombre).read_bytes()
    resp = _crear(cliente, original, nombre, par["publica_pem"])
    assert resp.status_code == 200
    j = resp.get_json()
    assert j["nombre"] == nombre + ".sobre.json"
    d = j["detalles"]
    assert d["tamano_original"] == len(original)
    assert d["sha256"] == hashlib.sha256(original).hexdigest()
    assert d["bits_rsa"] == 2048 and d["clave_cifrada_bytes"] == 256
    assert len(bytes.fromhex(d["iv_hex"])) == 16
    resp = _abrir(cliente, base64.b64decode(j["sobre_b64"]), par["privada_pem"])
    assert resp.status_code == 200
    r = resp.get_json()
    assert base64.b64decode(r["archivo_b64"]) == original
    assert r["nombre"] == nombre
    assert r["detalles"]["sha256"] == d["sha256"]


def test_crear_archivo_vacio(cliente, par):
    j = _crear(cliente, b"", "vacio.bin", par["publica_pem"]).get_json()
    r = _abrir(cliente, base64.b64decode(j["sobre_b64"]), par["privada_pem"])
    assert r.status_code == 200
    assert base64.b64decode(r.get_json()["archivo_b64"]) == b""


def test_crear_sin_archivo(cliente, par):
    resp = cliente.post(
        "/api/crear",
        data={"publica": _f(par["publica_pem"].encode(), "p.pem")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_crear_sin_publica(cliente):
    resp = cliente.post(
        "/api/crear", data={"archivo": _f(b"hola", "a.txt")}, content_type="multipart/form-data"
    )
    assert resp.status_code == 400


def test_crear_con_privada_en_lugar_de_publica(cliente, par):
    assert _crear(cliente, b"hola", "a.txt", par["privada_pem"]).status_code == 400


def test_crear_pem_basura(cliente):
    assert _crear(cliente, b"hola", "a.txt", "basura").status_code == 400


def test_abrir_con_publica_en_lugar_de_privada(cliente, par):
    j = _crear(cliente, b"hola", "a.txt", par["publica_pem"]).get_json()
    resp = _abrir(cliente, base64.b64decode(j["sobre_b64"]), par["publica_pem"])
    assert resp.status_code == 400


def test_abrir_llave_equivocada(cliente, par, otro_par):
    j = _crear(cliente, b"hola", "a.txt", par["publica_pem"]).get_json()
    resp = _abrir(cliente, base64.b64decode(j["sobre_b64"]), otro_par["privada_pem"])
    assert resp.status_code == 400
    assert "clave" in resp.get_json()["error"]


def test_abrir_sobre_alterado(cliente, par):
    j = _crear(cliente, b"hola", "a.txt", par["publica_pem"]).get_json()
    sobre = json.loads(base64.b64decode(j["sobre_b64"]))
    sobre["sha256_original"] = "0" * 64
    resp = _abrir(cliente, json.dumps(sobre).encode(), par["privada_pem"])
    assert resp.status_code == 400
    assert "alterado" in resp.get_json()["error"]


def test_abrir_no_json(cliente, par):
    assert _abrir(cliente, b"\xff\xfe no es json", par["privada_pem"]).status_code == 400


def test_clave_1024_rechazada(cliente):
    publica = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    resp = _crear(cliente, b"hola", "a.txt", publica_a_pem_sin_validar(publica))
    assert resp.status_code == 400


def publica_a_pem_sin_validar(publica) -> str:
    return publica.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def test_demo(cliente):
    resp = cliente.post("/api/demo")
    assert resp.status_code == 200
    j = resp.get_json()
    assert j["bits"] == 2048 and len(j["resultados"]) == 4
    for r in j["resultados"]:
        assert r["ok"] and r["sha256_original"] == r["sha256_recuperado"]


def test_peticion_grande(cliente, par):
    resp = _crear(cliente, b"\0" * (33 * 1024 * 1024), "grande.bin", par["publica_pem"])
    assert resp.status_code == 413
    assert resp.is_json
    assert "demasiado grande" in resp.get_json()["error"]


def test_main_no_tiene_cli():
    texto = (Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8")
    assert "argparse" not in texto and "sys.argv" not in texto
