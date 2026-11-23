"""Constantes y utilidades compartidas del formato del sobre digital."""
from pathlib import PurePosixPath, PureWindowsPath

VERSION = 1
ALGORITMOS = {
    "simetrico": "AES-256-CBC",
    "padding": "PKCS7",
    "asimetrico": "RSA-OAEP",
    "hash": "SHA-256",
    "mgf": "MGF1-SHA256",
}


def nombre_base(nombre: str) -> str:
    """Devuelve solo el nombre de archivo, sin rutas de Windows ni de POSIX."""
    return PurePosixPath(PureWindowsPath(str(nombre)).name).name
