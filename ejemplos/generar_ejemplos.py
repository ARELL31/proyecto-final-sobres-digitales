"""Genera los archivos de ejemplo (2 textos, 1 PNG y 1 PDF) en esta carpeta."""
import struct
import zlib
from pathlib import Path

DIRECTORIO = Path(__file__).parent


def crear_mensaje1() -> bytes:
    texto = (
        "Sobre digital: mensaje de prueba número 1.\n"
        "La criptografía híbrida combina AES y RSA para proteger la información.\n"
        "¡Mañana entregamos el proyecto final!\n"
    )
    return texto.encode("utf-8")


def crear_mensaje2() -> bytes:
    parrafo = (
        "El sobre digital cifra el archivo con una clave de sesión AES-256 y "
        "protege esa clave con la llave pública RSA del destinatario. "
        "Solo quien posea la llave privada puede recuperar el contenido.\n"
    )
    datos = ("Mensaje de prueba número 2 (texto largo).\n" + parrafo * 8).encode("utf-8")
    while len(datos) % 16 == 0:
        datos += b"."
    return datos


def _chunk_png(tipo: bytes, datos: bytes) -> bytes:
    cuerpo = tipo + datos
    return struct.pack(">I", len(datos)) + cuerpo + struct.pack(">I", zlib.crc32(cuerpo))


def crear_png(ancho: int = 64, alto: int = 64) -> bytes:
    filas = bytearray()
    for y in range(alto):
        filas.append(0)  # filtro: ninguno
        for x in range(ancho):
            filas += bytes((x * 255 // (ancho - 1), y * 255 // (alto - 1), 128))
    cabecera = struct.pack(">IIBBBBB", ancho, alto, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk_png(b"IHDR", cabecera)
        + _chunk_png(b"IDAT", zlib.compress(bytes(filas)))
        + _chunk_png(b"IEND", b"")
    )


def crear_pdf() -> bytes:
    contenido = b"BT /F1 18 Tf 72 720 Td (Sobre digital - documento de ejemplo) Tj ET"
    objetos = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(contenido)).encode() + b" >>\nstream\n"
        + contenido + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objetos, start=1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    inicio_xref = len(pdf)
    pdf += f"xref\n0 {len(objetos) + 1}\n".encode()
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode()
    pdf += (
        f"trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R >>\n"
        f"startxref\n{inicio_xref}\n%%EOF\n"
    ).encode()
    return bytes(pdf)


def main() -> None:
    archivos = {
        "mensaje1.txt": crear_mensaje1(),
        "mensaje2.txt": crear_mensaje2(),
        "imagen.png": crear_png(),
        "documento.pdf": crear_pdf(),
    }
    for nombre, datos in archivos.items():
        (DIRECTORIO / nombre).write_bytes(datos)
        print(f"{nombre}: {len(datos)} bytes")


if __name__ == "__main__":
    main()
