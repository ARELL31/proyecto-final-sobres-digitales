"""Lectura y apertura del sobre digital."""
import base64
import binascii
import hashlib
import hmac
import json

from cryptography.hazmat.primitives.asymmetric import rsa

from aes import TAM_IV, ErrorAES, descifrar_aes
from rsa_mod import ErrorRSA, descifrar_clave_sesion
from sobre_digital.generador_sobre_digital import (
    ALGORITMOS,
    VERSION,
    ErrorSobre,
    nombre_base,
)

_CAMPOS_B64 = ("clave_cifrada", "iv", "texto_cifrado")


def cargar_sobre(datos: bytes) -> dict:
    """Interpreta los bytes como un sobre digital (JSON UTF-8)."""
    try:
        sobre = json.loads(bytes(datos).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError) as e:
        raise ErrorSobre("el archivo no es un sobre digital válido (JSON UTF-8)") from e
    if not isinstance(sobre, dict):
        raise ErrorSobre("el sobre digital debe ser un objeto JSON")
    return sobre


def _campo_b64(sobre: dict, campo: str) -> bytes:
    valor = sobre.get(campo)
    if not isinstance(valor, str):
        raise ErrorSobre(f"falta el campo '{campo}' en el sobre")
    try:
        return base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ErrorSobre(f"el campo '{campo}' no es base64 válido") from e


def abrir_sobre(sobre: dict, privada: rsa.RSAPrivateKey) -> tuple[str, bytes]:
    """Abre el sobre: devuelve (nombre_original, datos) verificando SHA-256."""
    if not isinstance(sobre, dict):
        raise ErrorSobre("el sobre digital debe ser un objeto JSON")
    version = sobre.get("version")
    if isinstance(version, bool) or version != VERSION:
        raise ErrorSobre(f"versión de sobre no soportada: {version!r}")
    if sobre.get("algoritmos") != ALGORITMOS:
        raise ErrorSobre("algoritmos del sobre no soportados")
    nombre = sobre.get("nombre_original")
    hash_esperado = sobre.get("sha256_original")
    if not isinstance(nombre, str):
        raise ErrorSobre("falta el campo 'nombre_original' en el sobre")
    if not isinstance(hash_esperado, str):
        raise ErrorSobre("falta el campo 'sha256_original' en el sobre")
    clave_cifrada, iv, cifrado = (_campo_b64(sobre, c) for c in _CAMPOS_B64)
    if len(iv) != TAM_IV:
        raise ErrorSobre(f"el IV debe tener {TAM_IV} bytes, tiene {len(iv)}")

    try:
        clave = descifrar_clave_sesion(clave_cifrada, privada)
    except ErrorRSA as e:
        raise ErrorSobre(
            "no se pudo descifrar la clave de sesión: clave privada incorrecta "
            "o sobre alterado"
        ) from e
    try:
        datos = descifrar_aes(cifrado, clave, iv)
    except ErrorAES as e:
        raise ErrorSobre(
            f"no se pudo descifrar el contenido: sobre alterado ({e})"
        ) from e

    calculado = hashlib.sha256(datos).hexdigest()
    if not hmac.compare_digest(calculado.encode(), hash_esperado.lower().encode()):
        raise ErrorSobre("sobre alterado: el SHA-256 no coincide")
    return nombre_base(nombre), datos
