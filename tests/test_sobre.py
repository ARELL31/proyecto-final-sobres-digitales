import base64
import hashlib
import json

import pytest

from rsa_mod import generar_par_rsa
from sobre_digital import (
    ARCHIVOS_EJEMPLO,
    DIR_EJEMPLOS,
    ErrorSobre,
    abrir_sobre,
    cargar_sobre,
    crear_sobre,
    sobre_a_bytes,
)


@pytest.fixture(scope="module")
def par():
    return generar_par_rsa(2048)


@pytest.fixture(scope="module")
def par_ajeno():
    return generar_par_rsa(2048)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


@pytest.mark.parametrize("nombre", ARCHIVOS_EJEMPLO)
def test_ida_y_vuelta_ejemplos(nombre, par):
    privada, publica = par
    datos = (DIR_EJEMPLOS / nombre).read_bytes()
    sobre = cargar_sobre(sobre_a_bytes(crear_sobre(datos, nombre, publica)))
    nombre_rec, recuperado = abrir_sobre(sobre, privada)
    assert nombre_rec == nombre
    assert recuperado == datos


def test_archivo_vacio(par):
    privada, publica = par
    sobre = crear_sobre(b"", "vacio.txt", publica)
    assert abrir_sobre(sobre, privada) == ("vacio.txt", b"")


def test_campos_del_sobre(par):
    _, publica = par
    datos = b"contenido de prueba"
    s = crear_sobre(datos, "a.txt", publica)
    assert s["version"] == 1
    assert s["algoritmos"] == {
        "simetrico": "AES-256-CBC",
        "padding": "PKCS7",
        "asimetrico": "RSA-OAEP",
        "hash": "SHA-256",
        "mgf": "MGF1-SHA256",
    }
    assert s["bits_rsa"] == 2048
    assert len(base64.b64decode(s["iv"])) == 16
    assert len(base64.b64decode(s["clave_cifrada"])) == 256
    assert s["sha256_original"] == hashlib.sha256(datos).hexdigest()


def test_iv_y_clave_distintos_por_sobre(par):
    _, publica = par
    s1 = crear_sobre(b"igual", "a.txt", publica)
    s2 = crear_sobre(b"igual", "a.txt", publica)
    assert s1["iv"] != s2["iv"]
    assert s1["clave_cifrada"] != s2["clave_cifrada"]


def test_es_json_utf8(par):
    _, publica = par
    s = crear_sobre(b"x", "ñandú.txt", publica)
    assert json.loads(sobre_a_bytes(s).decode("utf-8")) == s


@pytest.mark.parametrize(
    "nombre, esperado",
    [("../../etc/passwd", "passwd"), ("C:\\x\\y.txt", "y.txt"), ("/tmp/a.png", "a.png")],
)
def test_nombre_saneado(nombre, esperado, par):
    privada, publica = par
    sobre = crear_sobre(b"x", nombre, publica)
    assert abrir_sobre(sobre, privada)[0] == esperado


def test_llave_equivocada(par, par_ajeno):
    _, publica = par
    sobre = crear_sobre(b"secreto", "a.txt", publica)
    with pytest.raises(ErrorSobre, match="clave"):
        abrir_sobre(sobre, par_ajeno[0])


def _invertir_byte(valor_b64: str) -> str:
    crudo = bytearray(base64.b64decode(valor_b64))
    crudo[0] ^= 0xFF
    return _b64(bytes(crudo))


@pytest.mark.parametrize("campo", ["texto_cifrado", "iv", "sha256_original", "clave_cifrada"])
def test_alterado(campo, par):
    privada, publica = par
    sobre = crear_sobre(b"contenido importante para alterar", "a.txt", publica)
    if campo == "sha256_original":
        sobre[campo] = hashlib.sha256(b"otro").hexdigest()
    else:
        sobre[campo] = _invertir_byte(sobre[campo])
    with pytest.raises(ErrorSobre):
        abrir_sobre(sobre, privada)


def test_alterado_mensaje_hash(par):
    privada, publica = par
    sobre = crear_sobre(b"datos", "a.txt", publica)
    sobre["sha256_original"] = hashlib.sha256(b"otro").hexdigest()
    with pytest.raises(ErrorSobre, match="alterado"):
        abrir_sobre(sobre, privada)


def test_version_invalida(par):
    privada, publica = par
    sobre = crear_sobre(b"x", "a.txt", publica)
    sobre["version"] = 2
    with pytest.raises(ErrorSobre):
        abrir_sobre(sobre, privada)


def _sin_iv(par) -> bytes:
    sobre = crear_sobre(b"x", "a.txt", par[1])
    del sobre["iv"]
    return json.dumps(sobre).encode()


def _iv_invalido(par) -> bytes:
    sobre = crear_sobre(b"x", "a.txt", par[1])
    sobre["iv"] = "%%%"
    return json.dumps(sobre).encode()


def _iv_corto(par) -> bytes:
    sobre = crear_sobre(b"x", "a.txt", par[1])
    sobre["iv"] = _b64(b"12345678")
    return json.dumps(sobre).encode()


@pytest.mark.parametrize(
    "fabrica",
    [
        lambda p: b"no es json",
        lambda p: b"\xff\xfe",
        lambda p: b"[]",
        _sin_iv,
        _iv_invalido,
        _iv_corto,
    ],
)
def test_sobre_invalido(fabrica, par):
    privada, _ = par
    with pytest.raises(ErrorSobre):
        abrir_sobre(cargar_sobre(fabrica(par)), privada)


@pytest.mark.parametrize("valor", [None, "2048", True])
def test_bits_rsa_invalido(valor, par):
    privada, publica = par
    sobre = crear_sobre(b"x", "a.txt", publica)
    if valor is None:
        del sobre["bits_rsa"]
    else:
        sobre["bits_rsa"] = valor
    with pytest.raises(ErrorSobre):
        abrir_sobre(sobre, privada)
