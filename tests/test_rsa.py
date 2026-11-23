import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from rsa_mod import (
    ErrorRSA,
    cargar_privada_pem,
    cargar_publica_pem,
    cifrar_clave_sesion,
    descifrar_clave_sesion,
    generar_par_rsa,
    guardar_par_rsa,
    privada_a_pem,
    publica_a_pem,
)


@pytest.fixture(scope="module")
def par2048():
    return generar_par_rsa(2048)


@pytest.fixture(scope="module")
def otro_par2048():
    return generar_par_rsa(2048)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_genera_2048_y_3072(bits):
    privada, publica = generar_par_rsa(bits)
    assert privada.key_size == bits
    assert privada.public_key().public_numbers().e == 65537
    assert publica.public_numbers().e == 65537


def test_rechaza_1024():
    with pytest.raises(ValueError):
        generar_par_rsa(1024)


def test_pem_separados(tmp_path, par2048):
    privada, publica = par2048
    ruta_priv, ruta_pub = guardar_par_rsa(privada, publica, tmp_path / "claves")
    assert ruta_priv.name == "private_key.pem"
    assert ruta_pub.name == "public_key.pem"
    assert ruta_priv.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert ruta_pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert cargar_privada_pem(ruta_priv.read_bytes()).key_size == 2048
    assert cargar_publica_pem(ruta_pub.read_bytes()).key_size == 2048


def test_oaep_ida_y_vuelta(par2048):
    privada, publica = par2048
    clave = bytes(range(32))
    cifrada = cifrar_clave_sesion(clave, publica)
    assert len(cifrada) == 256
    assert descifrar_clave_sesion(cifrada, privada) == clave


def test_oaep_es_aleatorio(par2048):
    _, publica = par2048
    clave = bytes(32)
    assert cifrar_clave_sesion(clave, publica) != cifrar_clave_sesion(clave, publica)


def test_llave_equivocada(par2048, otro_par2048):
    _, publica = par2048
    cifrada = cifrar_clave_sesion(bytes(32), publica)
    with pytest.raises(ErrorRSA):
        descifrar_clave_sesion(cifrada, otro_par2048[0])


def test_cifrado_alterado(par2048):
    privada, publica = par2048
    cifrada = bytearray(cifrar_clave_sesion(bytes(32), publica))
    cifrada[10] ^= 0xFF
    with pytest.raises(ErrorRSA):
        descifrar_clave_sesion(bytes(cifrada), privada)


def test_cargar_pem_invalido():
    with pytest.raises(ErrorRSA):
        cargar_publica_pem(b"basura")
    with pytest.raises(ErrorRSA):
        cargar_privada_pem(b"basura")


def test_cargar_tipo_equivocado(par2048):
    privada, publica = par2048
    with pytest.raises(ErrorRSA):
        cargar_privada_pem(publica_a_pem(publica))
    with pytest.raises(ErrorRSA):
        cargar_publica_pem(privada_a_pem(privada))


def test_cargar_clave_1024():
    privada = rsa.generate_private_key(65537, 1024)
    pem_priv = privada_a_pem(privada)
    pem_pub = publica_a_pem(privada.public_key())
    with pytest.raises(ErrorRSA):
        cargar_privada_pem(pem_priv)
    with pytest.raises(ErrorRSA):
        cargar_publica_pem(pem_pub)


def test_cargar_clave_no_rsa():
    privada = ec.generate_private_key(ec.SECP256R1())
    pem_priv = privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pem_pub = privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ErrorRSA):
        cargar_privada_pem(pem_priv)
    with pytest.raises(ErrorRSA):
        cargar_publica_pem(pem_pub)
