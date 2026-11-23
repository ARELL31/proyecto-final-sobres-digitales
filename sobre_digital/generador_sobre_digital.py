"""Creación del sobre digital: AES-256-CBC + RSA-OAEP + SHA-256."""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from aes import ErrorAES, cifrar_aes, generar_clave_aes
from rsa_mod import ErrorRSA, cifrar_clave_sesion
from sobre_digital.formato import ALGORITMOS, VERSION, nombre_base
from sobre_digital.lector_sobre_digital import ErrorSobre

ARCHIVOS_EJEMPLO = ("mensaje1.txt", "mensaje2.txt", "imagen.png", "documento.pdf")
DIR_EJEMPLOS = Path(__file__).resolve().parent.parent / "ejemplos"


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def crear_sobre(datos: bytes, nombre_original: str, publica: rsa.RSAPublicKey) -> dict:
    """Cifra `datos` y devuelve el sobre digital como diccionario."""
    if not isinstance(datos, (bytes, bytearray)):
        raise ErrorSobre("los datos del archivo deben ser de tipo bytes")
    if not isinstance(publica, rsa.RSAPublicKey):
        raise ErrorSobre("se requiere una clave pública RSA")
    datos = bytes(datos)
    clave = generar_clave_aes()
    try:
        iv, cifrado = cifrar_aes(datos, clave)
        clave_cifrada = cifrar_clave_sesion(clave, publica)
    except (ErrorAES, ErrorRSA) as e:
        raise ErrorSobre(f"no se pudo crear el sobre: {e}") from e
    return {
        "version": VERSION,
        "algoritmos": dict(ALGORITMOS),
        "bits_rsa": publica.key_size,
        "clave_cifrada": _b64(clave_cifrada),
        "iv": _b64(iv),
        "nombre_original": nombre_base(nombre_original),
        "sha256_original": hashlib.sha256(datos).hexdigest(),
        "texto_cifrado": _b64(cifrado),
    }


def sobre_a_bytes(sobre: dict) -> bytes:
    """Serializa el sobre como JSON UTF-8 con sangría."""
    return json.dumps(sobre, indent=2, ensure_ascii=False).encode("utf-8")
