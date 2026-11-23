# Diseño: Sobre digital AES-256-CBC + RSA-OAEP con GUI web

Fecha: 2026-11-22 · Entrega: 2026-11-23 (proyecto final individual de Criptografía)

## Intención

Construir desde cero un sistema de **sobre digital**: el contenido de un archivo se cifra con AES-256-CBC
usando una clave de sesión aleatoria, y esa clave se protege con RSA-OAEP (SHA-256). El profesor pidió
que la interacción sea **100 % por interfaz web** (sin CLI). Debe servir para la entrega y para una
exposición de 5 minutos con demo en vivo.

## Objetivos

- Cumplir y **probar con pytest** cada requisito criptográfico:
  - AES-256-CBC; clave de sesión de 32 bytes con CSPRNG (`os.urandom`/`secrets`).
  - IV aleatorio de 16 bytes nuevo en cada cifrado.
  - Relleno PKCS#7 (entradas que no son múltiplo de 16, y también las que sí lo son).
  - Archivos tratados como bytes binarios (round-trip exacto de PNG y PDF).
  - Clave de sesión cifrada con RSA-OAEP, hash SHA-256, MGF1-SHA256.
  - RSA de 2048 y 3072 bits; tamaños < 2048 se rechazan.
  - Claves en PEM separados: `private_key.pem` (PKCS#8, sin contraseña) y `public_key.pem` (SubjectPublicKeyInfo).
- Un solo sistema integrado con la estructura obligatoria (abajo).
- GUI web con Flask: generar claves, crear sobre, abrir sobre y demo.

## No objetivos

- Sin CLI: `main.py` solo arranca el servidor web (sin argparse ni subcomandos).
- Sin cuentas de usuario, base de datos ni almacenamiento en el servidor.
- Sin firma digital ni MAC (se documenta como limitación).
- Sin despliegue público: solo `127.0.0.1`.

## Anti-objetivos

- Implementar AES o RSA a mano: **todo** con `cryptography`.
- Abrir archivos en modo texto o transformarlos (decodificar, normalizar saltos de línea).
- Reutilizar código de la rama anterior `feature/sobre-digital`: se reescribe desde cero.

## Restricciones

- Python 3.12, `cryptography`, `Flask`, `pytest` (ya en `.venv`). `pdflatex` disponible para el reporte.
- Commits pequeños en español, **sin** `Co-Authored-By` ni atribución a Claude/Anthropic.
- Rama `feature/sobre-digital-web`.

## Enfoques considerados

| Enfoque | Ventaja | Costo |
|---|---|---|
| **A. Flask, una página + `fetch` con respuestas JSON** (elegido) | Descarga el resultado y muestra detalles en la misma operación; poco código; fácil de probar con el cliente de pruebas de Flask | Requiere algo de JavaScript |
| B. Flask con formularios clásicos y `send_file` | HTML más simple | No puede descargar y mostrar detalles a la vez sin guardar temporales en el servidor |
| C. Django | Estructura robusta | Configuración y boilerplate excesivos para una página |

El usuario dejó la elección del framework a criterio del constructor; se eligió A.

## Estructura

```text
main.py                 # arranca la app Flask en 127.0.0.1:5000
requirements.txt        # cryptography, Flask, pytest
README.md
GUIA_PRUEBAS.txt        # pasos para probar todo desde el navegador
rsa_mod/  __init__.py  generador_claves_rsa.py  cifrado_rsa.py
aes/      __init__.py  generador_claves_aes.py  cifrado_aes.py
sobre_digital/  __init__.py  generador_sobre_digital.py  lector_sobre_digital.py
gui/  __init__.py  app.py  templates/index.html
tests/   (pytest: un archivo por módulo + test_gui.py)
ejemplos/  mensaje1.txt  mensaje2.txt  imagen.png  documento.pdf
docs/  reporte.tex  reporte.pdf  presentacion.md
```

## Módulos (API)

Excepciones: `ErrorAES` (en `aes/cifrado_aes.py`), `ErrorRSA` (en `rsa_mod/cifrado_rsa.py`, también usada
por el generador de claves) y `ErrorSobre` (en `sobre_digital/lector_sobre_digital.py`), que envuelve a las otras dos
con mensajes en español. Cada `__init__.py` reexporta la API pública de su paquete.

- `aes/generador_claves_aes.py`
  - `generar_clave_aes() -> bytes` → 32 bytes con `secrets.token_bytes`.
  - `generar_iv() -> bytes` → 16 bytes con `os.urandom`.
- `aes/cifrado_aes.py`
  - `cifrar_aes(datos: bytes, clave: bytes) -> tuple[bytes, bytes]` → `(iv, cifrado)`; IV nuevo en cada llamada; PKCS#7 con `cryptography.hazmat.primitives.padding.PKCS7(128)`.
  - `descifrar_aes(cifrado: bytes, clave: bytes, iv: bytes) -> bytes`.
  - Valida clave de 32 bytes, IV de 16 bytes, cifrado no vacío y múltiplo de 16; relleno inválido → `ErrorAES`.
- `rsa_mod/generador_claves_rsa.py`
  - `generar_par_rsa(bits: int = 2048) -> (privada, publica)`; solo acepta 2048 y 3072 (`ValueError` si no); e = 65537.
  - `privada_a_pem(privada) -> bytes`, `publica_a_pem(publica) -> bytes`.
  - `cargar_privada_pem(datos: bytes)`, `cargar_publica_pem(datos: bytes)` → validan PEM, tipo RSA y tamaño ≥ 2048 (`ErrorRSA`).
  - `guardar_par_rsa(privada, publica, directorio) -> (ruta_priv, ruta_pub)` escribe `private_key.pem` y `public_key.pem`.
- `rsa_mod/cifrado_rsa.py`
  - `cifrar_clave_sesion(clave: bytes, publica) -> bytes` con `OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None)`.
  - `descifrar_clave_sesion(cifrada: bytes, privada) -> bytes`; fallo (llave equivocada, datos alterados) → `ErrorRSA`.
- `sobre_digital/generador_sobre_digital.py`
  - `crear_sobre(datos: bytes, nombre_original: str, publica) -> dict` y `sobre_a_bytes(sobre) -> bytes` (JSON UTF-8 indentado).
- `sobre_digital/lector_sobre_digital.py`
  - `cargar_sobre(datos: bytes) -> dict` (valida estructura) y `abrir_sobre(sobre: dict, privada) -> (nombre, datos)`; cualquier fallo → `ErrorSobre` con mensaje en español.

## Formato del sobre (`<nombre>.sobre.json`)

```json
{
  "version": 1,
  "algoritmos": {"simetrico": "AES-256-CBC", "padding": "PKCS7",
                 "asimetrico": "RSA-OAEP", "hash": "SHA-256", "mgf": "MGF1-SHA256"},
  "bits_rsa": 2048,
  "clave_cifrada": "<base64>",
  "iv": "<base64, 16 bytes>",
  "nombre_original": "imagen.png",
  "sha256_original": "<hex>",
  "texto_cifrado": "<base64>"
}
```

Validaciones al abrir: JSON objeto, campos presentes y de tipo correcto, `version == 1`, base64 válido,
IV de 16 bytes, clave de sesión descifrada de 32 bytes, relleno válido y SHA-256 coincidente
("sobre alterado"). `nombre_original` se reduce a su nombre base. El SHA-256 detecta alteraciones
accidentales o parciales pero no reemplaza un MAC/firma (limitación documentada).

## GUI web (`gui/app.py`)

`crear_app() -> Flask` (fábrica, para pruebas). `MAX_CONTENT_LENGTH` = 32 MB por petición completa (deja margen al
base64 del sobre; archivos originales de hasta ~20 MB). Todo en memoria. La carpeta `ejemplos/` se resuelve
relativa a la raíz del proyecto (`Path(__file__).resolve().parent.parent`), no al directorio actual.

| Ruta | Entrada | Respuesta JSON |
|---|---|---|
| `GET /` | — | página `index.html` |
| `POST /api/claves` | `bits` (2048/3072) | `{privada_pem, publica_pem, bits, tiempo_ms}` |
| `POST /api/crear` | `archivo`, `publica` (archivos) | `{nombre, sobre_b64, detalles:{tamano_original, tamano_cifrado, iv_hex, clave_cifrada_bytes, sha256}}` |
| `POST /api/abrir` | `sobre`, `privada` (archivos) | `{nombre, archivo_b64, detalles:{tamano, sha256, bits_rsa}}` (solo si el SHA-256 coincide; si no, 400 "sobre alterado") |
| `POST /api/demo` | `bits` opcional (2048 por defecto); genera un par RSA nuevo en cada llamada y no devuelve claves | `{resultados:[{archivo, tamano, sha256_original, sha256_recuperado, ok, iv_hex}]}` sobre los 4 archivos de `ejemplos/` |

Errores → HTTP 400 con `{"error": "<mensaje claro en español>"}` (falta archivo, PEM inválido, clave < 2048,
llave equivocada, sobre alterado, archivo demasiado grande → 413).

`index.html`: una página en español con 4 tarjetas (Generar claves, Crear sobre, Abrir sobre, Demo),
cada una con su formulario; el JavaScript envía con `fetch`, descarga los archivos devueltos
(Blob desde base64) y muestra los detalles o el error en la tarjeta. Sin dependencias externas (CSS y JS inline).

`main.py`: `crear_app().run(host="127.0.0.1", port=5000)` y muestra la URL en consola.

## Pruebas

- `tests/test_aes.py`: clave 32 bytes y distinta cada vez; IV 16 bytes y distinto en cada cifrado del mismo texto;
  round-trip con longitudes 0, 1, 15, 16, 17, 1000; longitud del cifrado múltiplo de 16 y con bloque extra
  cuando la entrada es múltiplo de 16; clave/IV de tamaño incorrecto y relleno inválido fallan.
- `tests/test_rsa.py`: 2048 y 3072; 1024 rechazado; PEM separados con los nombres correctos; round-trip OAEP;
  llave privada equivocada falla; ciphertext OAEP del tamaño del módulo; carga de PEM inválido falla.
- `tests/test_sobre.py`: round-trip de los 4 ejemplos byte a byte; campos y longitudes; sobre alterado
  (texto cifrado, IV, hash, versión) falla; llave equivocada falla; nombre con ruta se sanea.
- `tests/test_gui.py`: cada ruta con el cliente de pruebas de Flask, incluidos los errores.

## Documentación

- `README.md`: instalación, `python main.py`, uso de la página, estructura, formato del sobre.
- `GUIA_PRUEBAS.txt`: pasos numerados para probar cada función y cada error desde el navegador.
- `docs/reporte.tex` → `docs/reporte.pdf` con `pdflatex`: introducción, fundamentos (AES-CBC, PKCS#7, RSA-OAEP,
  sobre digital), diseño, implementación, pruebas y resultados reales, limitaciones, conclusiones.
  Autor: Luis Fernando Franco Arellano.
- `docs/presentacion.md`: guion de 5 minutos con demo.

## Decisiones del constructor (no consultadas)

- El formato del sobre no lo fija la tarea: lo define este diseño.
- Todos los entregables de la estructura son obligatorios (incluidos `reporte.pdf` y `presentacion.md`);
  orden: código y pruebas primero, documentación después con resultados reales de pytest y de la demo.
- Hash que no coincide al abrir → error 400 "sobre alterado"; nunca se devuelven datos sin verificar.

- Framework Flask y enfoque A.
- Sobre en JSON + base64 con SHA-256 del original.
- Clave privada PEM sin contraseña (requisito no la pide; se menciona como mejora).
- Ejemplos binarios generados con un script reproducible (`ejemplos/generar_ejemplos.py`, PNG con `zlib`,
  PDF mínimo escrito a mano) y versionados.
