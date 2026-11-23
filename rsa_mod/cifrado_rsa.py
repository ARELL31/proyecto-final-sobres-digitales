"""Cifrado de la clave de sesión con RSA-OAEP (SHA-256)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class ErrorRSA(Exception):
    """Error en una operación RSA (claves o datos inválidos)."""


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )


def cifrar_clave_sesion(clave: bytes, publica: rsa.RSAPublicKey) -> bytes:
    """Cifra la clave de sesión con la clave pública usando RSA-OAEP-SHA256."""
    if not isinstance(clave, (bytes, bytearray)):
        raise ErrorRSA("la clave de sesión debe ser de tipo bytes")
    if not isinstance(publica, rsa.RSAPublicKey):
        raise ErrorRSA("se requiere una clave pública RSA")
    try:
        return publica.encrypt(bytes(clave), _oaep())
    except ValueError as e:
        raise ErrorRSA("no se pudo cifrar la clave de sesión con RSA") from e


def descifrar_clave_sesion(cifrada: bytes, privada: rsa.RSAPrivateKey) -> bytes:
    """Descifra la clave de sesión con la clave privada (RSA-OAEP-SHA256)."""
    if not isinstance(cifrada, (bytes, bytearray)):
        raise ErrorRSA("la clave cifrada debe ser de tipo bytes")
    if not isinstance(privada, rsa.RSAPrivateKey):
        raise ErrorRSA("se requiere una clave privada RSA")
    try:
        return privada.decrypt(bytes(cifrada), _oaep())
    except ValueError as e:
        raise ErrorRSA(
            "no se pudo descifrar la clave de sesión: clave privada incorrecta "
            "o datos alterados"
        ) from e
