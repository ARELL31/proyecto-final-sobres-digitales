"""Cifrado y descifrado AES-256-CBC con relleno PKCS#7."""
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from aes.generador_claves_aes import TAM_CLAVE, TAM_IV, generar_iv

TAM_BLOQUE = 16


class ErrorAES(Exception):
    """Error en una operación AES (parámetros o datos inválidos)."""


def _validar_bytes(valor, nombre: str) -> None:
    if not isinstance(valor, (bytes, bytearray)):
        raise ErrorAES(f"{nombre} debe ser de tipo bytes")


def _validar_clave(clave: bytes) -> None:
    _validar_bytes(clave, "la clave")
    if len(clave) != TAM_CLAVE:
        raise ErrorAES(f"la clave debe tener {TAM_CLAVE} bytes, tiene {len(clave)}")


def cifrar_aes(datos: bytes, clave: bytes) -> tuple[bytes, bytes]:
    """Cifra `datos` con AES-256-CBC y un IV nuevo. Devuelve (iv, cifrado)."""
    _validar_bytes(datos, "los datos")
    _validar_clave(clave)
    iv = generar_iv()
    relleno = padding.PKCS7(TAM_BLOQUE * 8).padder()
    rellenados = relleno.update(bytes(datos)) + relleno.finalize()
    cifrador = Cipher(algorithms.AES(bytes(clave)), modes.CBC(iv)).encryptor()
    return iv, cifrador.update(rellenados) + cifrador.finalize()


def descifrar_aes(cifrado: bytes, clave: bytes, iv: bytes) -> bytes:
    """Descifra `cifrado` con AES-256-CBC y quita el relleno PKCS#7."""
    _validar_bytes(cifrado, "el cifrado")
    _validar_clave(clave)
    _validar_bytes(iv, "el IV")
    if len(iv) != TAM_IV:
        raise ErrorAES(f"el IV debe tener {TAM_IV} bytes, tiene {len(iv)}")
    if len(cifrado) == 0 or len(cifrado) % TAM_BLOQUE != 0:
        raise ErrorAES("la longitud del cifrado debe ser un múltiplo de 16 bytes")
    descifrador = Cipher(algorithms.AES(bytes(clave)), modes.CBC(bytes(iv))).decryptor()
    rellenados = descifrador.update(bytes(cifrado)) + descifrador.finalize()
    quitar = padding.PKCS7(TAM_BLOQUE * 8).unpadder()
    try:
        return quitar.update(rellenados) + quitar.finalize()
    except ValueError as e:
        raise ErrorAES(
            "relleno PKCS#7 inválido: clave incorrecta o datos alterados"
        ) from e
