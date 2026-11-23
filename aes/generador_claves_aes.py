"""Generación de claves e IV aleatorios para AES-256-CBC."""
import os
import secrets

TAM_CLAVE = 32  # bytes (AES-256)
TAM_IV = 16  # bytes (tamaño de bloque AES)


def generar_clave_aes() -> bytes:
    """Genera una clave AES-256 aleatoria de 32 bytes."""
    return secrets.token_bytes(TAM_CLAVE)


def generar_iv() -> bytes:
    """Genera un vector de inicialización aleatorio de 16 bytes."""
    return os.urandom(TAM_IV)
