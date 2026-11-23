import os

import pytest

from aes import (
    ErrorAES,
    cifrar_aes,
    descifrar_aes,
    generar_clave_aes,
    generar_iv,
)


def test_clave_32_bytes_y_aleatoria():
    assert len(generar_clave_aes()) == 32
    assert generar_clave_aes() != generar_clave_aes()


def test_iv_16_bytes():
    assert len(generar_iv()) == 16


def test_iv_distinto_en_cada_cifrado():
    clave = generar_clave_aes()
    iv1, c1 = cifrar_aes(b"mismo texto", clave)
    iv2, c2 = cifrar_aes(b"mismo texto", clave)
    assert iv1 != iv2
    assert c1 != c2


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_ida_y_vuelta(n):
    clave = generar_clave_aes()
    datos = os.urandom(n)
    iv, cifrado = cifrar_aes(datos, clave)
    assert descifrar_aes(cifrado, clave, iv) == datos


@pytest.mark.parametrize("n, esperado", [(17, 32), (16, 32), (0, 16)])
def test_pkcs7_longitudes(n, esperado):
    _, cifrado = cifrar_aes(b"a" * n, generar_clave_aes())
    assert len(cifrado) == esperado


def test_bytes_binarios():
    clave = generar_clave_aes()
    datos = bytes(range(256)) * 4
    iv, cifrado = cifrar_aes(datos, clave)
    assert descifrar_aes(cifrado, clave, iv) == datos


def test_clave_invalida():
    with pytest.raises(ErrorAES):
        cifrar_aes(b"x", b"corta")
    iv, cifrado = cifrar_aes(b"x", generar_clave_aes())
    with pytest.raises(ErrorAES):
        descifrar_aes(cifrado, os.urandom(16), iv)


def test_iv_invalido():
    clave = generar_clave_aes()
    _, cifrado = cifrar_aes(b"x", clave)
    with pytest.raises(ErrorAES):
        descifrar_aes(cifrado, clave, os.urandom(8))


def test_cifrado_no_multiplo_de_16():
    with pytest.raises(ErrorAES):
        descifrar_aes(b"\x00" * 15, generar_clave_aes(), generar_iv())


def test_relleno_invalido():
    iv, cifrado = cifrar_aes(b"mensaje secreto", generar_clave_aes())
    errores = 0
    for _ in range(20):
        try:
            descifrar_aes(cifrado, generar_clave_aes(), iv)
        except ErrorAES:
            errores += 1
    assert errores >= 1
