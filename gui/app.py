"""API Flask del sobre digital."""
import base64
import hashlib
import time

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from rsa_mod import (
    TAMANOS_PERMITIDOS,
    ErrorRSA,
    cargar_privada_pem,
    cargar_publica_pem,
    generar_par_rsa,
    privada_a_pem,
    publica_a_pem,
)
from sobre_digital import (
    ARCHIVOS_EJEMPLO,
    DIR_EJEMPLOS,
    ErrorSobre,
    abrir_sobre,
    cargar_sobre,
    crear_sobre,
    sobre_a_bytes,
)

MAX_BYTES = 32 * 1024 * 1024


class _ErrorPeticion(Exception):
    """Petición mal formada (campo ausente o inválido)."""


def _leer_archivo(campo: str):
    """Devuelve (nombre, bytes) del archivo subido en `campo`."""
    archivo = request.files.get(campo)
    if archivo is None or not archivo.filename:
        raise _ErrorPeticion(f"falta el archivo '{campo}'")
    return archivo.filename, archivo.read()


def _bits(valor, por_defecto=None) -> int:
    if valor in (None, "") and por_defecto is not None:
        return por_defecto
    try:
        bits = int(valor)
    except (TypeError, ValueError):
        raise _ErrorPeticion("el tamaño de clave debe ser un número entero") from None
    if bits not in TAMANOS_PERMITIDOS:
        permitidos = ", ".join(str(t) for t in TAMANOS_PERMITIDOS)
        raise _ErrorPeticion(f"tamaño de clave no permitido (use {permitidos})")
    return bits


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def crear_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

    @app.errorhandler(_ErrorPeticion)
    @app.errorhandler(ErrorRSA)
    @app.errorhandler(ErrorSobre)
    @app.errorhandler(ValueError)
    def _error_400(e):
        return jsonify({"error": str(e)}), 400

    @app.errorhandler(RequestEntityTooLarge)
    def _error_413(_e):
        return jsonify({"error": "archivo demasiado grande (máximo 32 MB)"}), 413

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/api/claves")
    def api_claves():
        bits = _bits(request.form.get("bits"))
        inicio = time.perf_counter()
        privada, publica = generar_par_rsa(bits)
        ms = int((time.perf_counter() - inicio) * 1000)
        return jsonify(
            privada_pem=privada_a_pem(privada).decode("ascii"),
            publica_pem=publica_a_pem(publica).decode("ascii"),
            bits=bits,
            tiempo_ms=ms,
        )

    @app.post("/api/crear")
    def api_crear():
        nombre, datos = _leer_archivo("archivo")
        _, pem = _leer_archivo("publica")
        publica = cargar_publica_pem(pem)
        sobre = crear_sobre(datos, nombre, publica)
        contenido = sobre_a_bytes(sobre)
        return jsonify(
            nombre=f"{sobre['nombre_original']}.sobre.json",
            sobre_b64=_b64(contenido),
            detalles={
                "tamano_original": len(datos),
                "tamano_cifrado": len(base64.b64decode(sobre["texto_cifrado"])),
                "iv_hex": base64.b64decode(sobre["iv"]).hex(),
                "clave_cifrada_bytes": len(base64.b64decode(sobre["clave_cifrada"])),
                "sha256": sobre["sha256_original"],
                "bits_rsa": sobre["bits_rsa"],
            },
        )

    @app.post("/api/abrir")
    def api_abrir():
        _, contenido = _leer_archivo("sobre")
        _, pem = _leer_archivo("privada")
        sobre = cargar_sobre(contenido)
        privada = cargar_privada_pem(pem)
        nombre, datos = abrir_sobre(sobre, privada)
        return jsonify(
            nombre=nombre,
            archivo_b64=_b64(datos),
            detalles={
                "tamano": len(datos),
                "sha256": hashlib.sha256(datos).hexdigest(),
                "bits_rsa": privada.key_size,
            },
        )

    @app.post("/api/demo")
    def api_demo():
        bits = _bits(request.form.get("bits"), 2048)
        privada, publica = generar_par_rsa(bits)
        resultados = []
        for nombre in ARCHIVOS_EJEMPLO:
            datos = (DIR_EJEMPLOS / nombre).read_bytes()
            sobre = crear_sobre(datos, nombre, publica)
            _, recuperado = abrir_sobre(cargar_sobre(sobre_a_bytes(sobre)), privada)
            original = hashlib.sha256(datos).hexdigest()
            recup = hashlib.sha256(recuperado).hexdigest()
            resultados.append(
                {
                    "archivo": nombre,
                    "tamano": len(datos),
                    "sha256_original": original,
                    "sha256_recuperado": recup,
                    "ok": recuperado == datos and original == recup,
                    "iv_hex": base64.b64decode(sobre["iv"]).hex(),
                }
            )
        return jsonify(bits=bits, resultados=resultados)

    return app
