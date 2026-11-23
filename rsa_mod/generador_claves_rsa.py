"""Generación, serialización PEM y carga de claves RSA."""
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from rsa_mod.cifrado_rsa import ErrorRSA

TAMANOS_PERMITIDOS = (2048, 3072)
TAM_MINIMO = 2048
EXPONENTE_PUBLICO = 65537


def generar_par_rsa(bits: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Genera un par de claves RSA de 2048 o 3072 bits (e = 65537)."""
    if bits not in TAMANOS_PERMITIDOS:
        raise ValueError(
            f"tamaño de clave no permitido: {bits}; use {TAMANOS_PERMITIDOS}"
        )
    privada = rsa.generate_private_key(EXPONENTE_PUBLICO, bits)
    return privada, privada.public_key()


def privada_a_pem(privada: rsa.RSAPrivateKey) -> bytes:
    """Serializa la clave privada en PEM (PKCS#8, sin cifrar)."""
    return privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def publica_a_pem(publica: rsa.RSAPublicKey) -> bytes:
    """Serializa la clave pública en PEM (SubjectPublicKeyInfo)."""
    return publica.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _validar_rsa(clave, tipo, nombre: str):
    if not isinstance(clave, tipo):
        raise ErrorRSA(f"la clave {nombre} cargada no es una clave RSA")
    if clave.key_size < TAM_MINIMO:
        raise ErrorRSA(
            f"la clave {nombre} es de {clave.key_size} bits; "
            f"el mínimo permitido es {TAM_MINIMO}"
        )
    return clave


def cargar_privada_pem(datos: bytes) -> rsa.RSAPrivateKey:
    """Carga una clave privada RSA desde PEM; exige al menos 2048 bits."""
    try:
        clave = serialization.load_pem_private_key(datos, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise ErrorRSA("el archivo no es una clave privada PEM válida") from e
    return _validar_rsa(clave, rsa.RSAPrivateKey, "privada")


def cargar_publica_pem(datos: bytes) -> rsa.RSAPublicKey:
    """Carga una clave pública RSA desde PEM; exige al menos 2048 bits."""
    try:
        clave = serialization.load_pem_public_key(datos)
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise ErrorRSA("el archivo no es una clave pública PEM válida") from e
    return _validar_rsa(clave, rsa.RSAPublicKey, "pública")


def guardar_par_rsa(
    privada: rsa.RSAPrivateKey, publica: rsa.RSAPublicKey, directorio: str | Path
) -> tuple[Path, Path]:
    """Guarda `private_key.pem` y `public_key.pem` en `directorio`."""
    carpeta = Path(directorio)
    carpeta.mkdir(parents=True, exist_ok=True)
    ruta_privada = carpeta / "private_key.pem"
    ruta_publica = carpeta / "public_key.pem"
    ruta_privada.write_bytes(privada_a_pem(privada))
    ruta_publica.write_bytes(publica_a_pem(publica))
    return ruta_privada, ruta_publica
