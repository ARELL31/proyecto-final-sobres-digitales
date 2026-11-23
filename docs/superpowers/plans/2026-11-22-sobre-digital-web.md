# Sobre digital con GUI web — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sistema de sobre digital (AES-256-CBC + RSA-OAEP-SHA256) operado 100 % desde una página web Flask.

**Architecture:** Paquetes `aes/`, `rsa_mod/` y `sobre_digital/` con funciones puras sobre `bytes`; `gui/app.py`
expone una API JSON (fábrica `crear_app()`) que consume esas funciones en memoria; `index.html` llama a la API
con `fetch`. `main.py` solo arranca el servidor.

**Tech Stack:** Python 3.12, cryptography 50, Flask 3.1, pytest 9. LaTeX (`pdflatex`) para el reporte.

**Spec:** `docs/superpowers/specs/2026-11-22-sobre-digital-web-design.md`

## Global Constraints

- NO implementar AES ni RSA a mano: solo `cryptography` (`hazmat.primitives.ciphers`, `padding.PKCS7(128)`, `asymmetric.rsa`, `asymmetric.padding.OAEP`).
- AES-256-CBC; clave 32 bytes con `secrets.token_bytes(32)`; IV 16 bytes con `os.urandom(16)` nuevo en cada cifrado.
- OAEP: `padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)`.
- RSA: solo 2048 y 3072 bits para generar; claves cargadas < 2048 → error. e = 65537.
- PEM: `private_key.pem` (PKCS8, `NoEncryption`) y `public_key.pem` (SubjectPublicKeyInfo).
- Todo en `bytes`; nunca abrir archivos de datos en modo texto.
- Sin CLI: `main.py` sin argparse ni subcomandos.
- Mensajes de error y textos de UI en español.
- Commits pequeños en español. **PROHIBIDO** añadir `Co-Authored-By` o cualquier atribución a Claude/Anthropic en commits.
- Ejecutar pruebas con `.venv/bin/pytest` desde la raíz del proyecto.

## Review Focus

- Archivo vacío (0 bytes): debe cifrarse y recuperarse como 0 bytes (prueba en Task 3 y Task 4).
- Nombre de archivo con ruta o recorrido (`../../etc/passwd`, `C:\x\y.txt`): el nombre recuperado es solo el nombre base (Task 3).
- Llaves intercambiadas (subir la pública donde va la privada y viceversa): 400 con mensaje claro, no 500 (Task 4).
- Sobre que no es JSON / no UTF-8 / JSON lista en vez de objeto: 400 "sobre inválido" (Task 3 y Task 4).
- Petición > 32 MB: 413 con JSON `{"error": ...}`, no la página HTML por defecto de Flask (Task 4).

---

### Task 1: Base del proyecto y módulo AES

**Files:**
- Create: `requirements.txt` (`cryptography>=42`, `Flask>=3.0`, `pytest>=8`), `pytest.ini` (`[pytest]` `testpaths = tests`, `pythonpath = .`), `.gitignore` (añadir `__pycache__/`, `.pytest_cache/`, `.superpowers/`, `.venv/`, `docs/*.aux`, `docs/*.log`, `docs/*.out`, `docs/*.toc`)
- Create: `aes/__init__.py`, `aes/generador_claves_aes.py`, `aes/cifrado_aes.py`, `tests/__init__.py`
- Test: `tests/test_aes.py`

**Interfaces:**
- Produces: `generar_clave_aes() -> bytes`, `generar_iv() -> bytes`, `cifrar_aes(datos: bytes, clave: bytes) -> tuple[bytes, bytes]` (iv, cifrado), `descifrar_aes(cifrado: bytes, clave: bytes, iv: bytes) -> bytes`, `class ErrorAES(Exception)`, constantes `TAM_CLAVE = 32`, `TAM_IV = 16`. Todo reexportado desde `aes`.

- [ ] **Step 1: Write the failing tests** en `tests/test_aes.py`:
  - `test_clave_32_bytes_y_aleatoria`: `len(generar_clave_aes()) == 32` y dos llamadas distintas.
  - `test_iv_16_bytes`: `len(generar_iv()) == 16`.
  - `test_iv_distinto_en_cada_cifrado`: cifrar el mismo texto dos veces con la misma clave → IVs distintos y cifrados distintos.
  - `test_ida_y_vuelta` parametrizado con longitudes `[0, 1, 15, 16, 17, 1000]` usando `os.urandom(n)` → recuperado `==` original.
  - `test_pkcs7_longitudes`: entrada de 17 bytes → cifrado de 32; de 16 → 32 (bloque extra completo); de 0 → 16.
  - `test_bytes_binarios`: datos `bytes(range(256)) * 4` (incluye `\x00`, `\r\n`, `\xff`) vuelven idénticos.
  - `test_clave_invalida`: `cifrar_aes(b"x", b"corta")` y `descifrar_aes(..., clave de 16 bytes, ...)` → `ErrorAES`.
  - `test_iv_invalido`: descifrar con IV de 8 bytes → `ErrorAES`.
  - `test_cifrado_no_multiplo_de_16`: `descifrar_aes(b"\x00"*15, clave, iv)` → `ErrorAES`.
  - `test_relleno_invalido`: descifrar con otra clave (aleatoria) un cifrado válido → `ErrorAES` o resultado distinto; repetir hasta 20 veces y exigir al menos un `ErrorAES` (relleno inválido detectado).

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_aes.py -v` → FAIL (`ModuleNotFoundError: aes`).

- [ ] **Step 3: Implement** en `aes/generador_claves_aes.py` (secrets/os) y `aes/cifrado_aes.py` (`Cipher(algorithms.AES(clave), modes.CBC(iv))` + `padding.PKCS7(128)`; `ValueError` del unpadder → `ErrorAES("relleno PKCS#7 inválido: clave incorrecta o datos alterados")`). Validar tipos/tamaños antes de llamar a la biblioteca.

- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_aes.py -v` → todas PASS.

- [ ] **Step 5: Commit** `git add requirements.txt pytest.ini .gitignore aes tests && git commit -m "feat: módulo AES-256-CBC con PKCS#7 e IV aleatorio"`

### Task 2: Módulo RSA (claves PEM y OAEP)

**Files:**
- Create: `rsa_mod/__init__.py`, `rsa_mod/generador_claves_rsa.py`, `rsa_mod/cifrado_rsa.py`
- Test: `tests/test_rsa.py`

**Interfaces:**
- Produces (reexportado desde `rsa_mod`): `class ErrorRSA(Exception)` (en `cifrado_rsa.py`), `TAMANOS_PERMITIDOS = (2048, 3072)`, `TAM_MINIMO = 2048`,
  `generar_par_rsa(bits: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]` (`ValueError` si bits no permitido),
  `privada_a_pem(privada) -> bytes`, `publica_a_pem(publica) -> bytes`,
  `cargar_privada_pem(datos: bytes) -> RSAPrivateKey`, `cargar_publica_pem(datos: bytes) -> RSAPublicKey` (`ErrorRSA` si no es PEM, no es RSA, es del tipo equivocado o < 2048 bits),
  `guardar_par_rsa(privada, publica, directorio: str | Path) -> tuple[Path, Path]` (crea el directorio; escribe `private_key.pem`, `public_key.pem`),
  `cifrar_clave_sesion(clave: bytes, publica) -> bytes`, `descifrar_clave_sesion(cifrada: bytes, privada) -> bytes` (`ErrorRSA` si falla).

- [ ] **Step 1: Write the failing tests** en `tests/test_rsa.py` (fixture `par2048` con `scope="module"`):
  - `test_genera_2048_y_3072` parametrizado: `privada.key_size == bits` y `public_numbers().e == 65537`.
  - `test_rechaza_1024`: `generar_par_rsa(1024)` → `ValueError`.
  - `test_pem_separados(tmp_path)`: `guardar_par_rsa` crea `private_key.pem` que empieza con `b"-----BEGIN PRIVATE KEY-----"` y `public_key.pem` con `b"-----BEGIN PUBLIC KEY-----"`; ambos cargan de vuelta.
  - `test_oaep_ida_y_vuelta`: clave de 32 bytes → cifrada de `256` bytes (2048) → descifrada igual.
  - `test_oaep_es_aleatorio`: cifrar dos veces la misma clave → resultados distintos.
  - `test_llave_equivocada`: descifrar con otro par → `ErrorRSA`.
  - `test_cifrado_alterado`: invertir un byte → `ErrorRSA`.
  - `test_cargar_pem_invalido`: `cargar_publica_pem(b"basura")` y `cargar_privada_pem(b"basura")` → `ErrorRSA`.
  - `test_cargar_tipo_equivocado`: `cargar_privada_pem(pem_publica)` y `cargar_publica_pem(pem_privada)` → `ErrorRSA`.
  - `test_cargar_clave_1024`: PEM de una clave de 1024 generada directamente con `rsa.generate_private_key` → `ErrorRSA` al cargar (privada y pública).
  - `test_cargar_clave_no_rsa`: PEM de una clave `ec.generate_private_key(ec.SECP256R1())` → `ErrorRSA`.

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_rsa.py -v` → FAIL.
- [ ] **Step 3: Implement** con `rsa.generate_private_key(65537, bits)`, `serialization.load_pem_private_key(datos, password=None)` / `load_pem_public_key`; capturar `ValueError`, `TypeError`, `UnsupportedAlgorithm` → `ErrorRSA` en español. OAEP según Global Constraints.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/test_rsa.py -v` → PASS.
- [ ] **Step 5: Commit** `git add rsa_mod tests/test_rsa.py && git commit -m "feat: módulo RSA-OAEP-SHA256 con claves PEM separadas"`

### Task 3: Archivos de ejemplo y sobre digital

**Files:**
- Create: `ejemplos/generar_ejemplos.py`, `ejemplos/mensaje1.txt`, `ejemplos/mensaje2.txt`, `ejemplos/imagen.png`, `ejemplos/documento.pdf`
- Create: `sobre_digital/__init__.py`, `sobre_digital/generador_sobre_digital.py`, `sobre_digital/lector_sobre_digital.py`
- Test: `tests/test_sobre.py`

**Interfaces:**
- Consumes: Task 1 (`cifrar_aes`, `descifrar_aes`, `generar_clave_aes`, `ErrorAES`), Task 2 (`cifrar_clave_sesion`, `descifrar_clave_sesion`, `ErrorRSA`).
- Produces (reexportado desde `sobre_digital`): `VERSION = 1`, `ARCHIVOS_EJEMPLO = ("mensaje1.txt", "mensaje2.txt", "imagen.png", "documento.pdf")`, `DIR_EJEMPLOS: Path` (raíz del proyecto / `ejemplos`),
  `crear_sobre(datos: bytes, nombre_original: str, publica) -> dict`, `sobre_a_bytes(sobre: dict) -> bytes`,
  `cargar_sobre(datos: bytes) -> dict`, `abrir_sobre(sobre: dict, privada) -> tuple[str, bytes]`, `class ErrorSobre(Exception)`.
- Campos del dict exactamente como en la spec: `version`, `algoritmos`, `bits_rsa`, `clave_cifrada`, `iv`, `nombre_original`, `sha256_original`, `texto_cifrado`.

- [ ] **Step 1: Ejemplos.** `generar_ejemplos.py` escribe (con `Path(__file__).parent`, en modo `wb`): `mensaje1.txt` (texto en español con acentos y ñ, ~3 líneas, UTF-8), `mensaje2.txt` (texto más largo, >1 KB, tamaño NO múltiplo de 16), `imagen.png` (PNG válido 64×64 RGB con degradado, construido con `zlib` + `struct` + CRC), `documento.pdf` (PDF 1.4 mínimo válido de una página con texto, offsets de xref calculados). Ejecutar `.venv/bin/python ejemplos/generar_ejemplos.py`; verificar con `file ejemplos/*` → "PNG image data, 64 x 64" y "PDF document, version 1.4".

- [ ] **Step 2: Write the failing tests** en `tests/test_sobre.py` (fixture de módulo con un par 2048 y otro par 2048 "ajeno"):
  - `test_ida_y_vuelta_ejemplos` parametrizado sobre `ARCHIVOS_EJEMPLO`: leer bytes, `crear_sobre` → `sobre_a_bytes` → `cargar_sobre` → `abrir_sobre` → nombre igual y datos `==` originales.
  - `test_archivo_vacio`: `b""` vuelve como `b""`.
  - `test_campos_del_sobre`: `version == 1`, `algoritmos == {"simetrico": "AES-256-CBC", "padding": "PKCS7", "asimetrico": "RSA-OAEP", "hash": "SHA-256", "mgf": "MGF1-SHA256"}`, `bits_rsa == 2048`, `len(b64decode(iv)) == 16`, `len(b64decode(clave_cifrada)) == 256`, `sha256_original == hashlib.sha256(datos).hexdigest()`.
  - `test_iv_y_clave_distintos_por_sobre`: dos sobres del mismo archivo → `iv` y `clave_cifrada` distintos.
  - `test_es_json_utf8`: `json.loads(sobre_a_bytes(s).decode("utf-8"))` funciona.
  - `test_nombre_saneado` parametrizado con `"../../etc/passwd"`, `"C:\\x\\y.txt"`, `"/tmp/a.png"` → nombre recuperado `"passwd"`, `"y.txt"`, `"a.png"`.
  - `test_llave_equivocada` → `ErrorSobre`.
  - `test_alterado` parametrizado: modificar `texto_cifrado` (invertir un byte del contenido decodificado y recodificar), `iv`, `sha256_original` (otro hex), `clave_cifrada` → `ErrorSobre`.
  - `test_version_invalida`: `version = 2` → `ErrorSobre`.
  - `test_sobre_invalido` parametrizado con `b"no es json"`, `b"\xff\xfe"`, `b"[]"`, JSON sin `iv`, JSON con `iv` = `"%%%"` (base64 inválido), JSON con `iv` de 8 bytes → `ErrorSobre` (en `cargar_sobre` o `abrir_sobre`).

- [ ] **Step 3: Run** `.venv/bin/pytest tests/test_sobre.py -v` → FAIL.
- [ ] **Step 4: Implement** generador y lector. Lector: `base64.b64decode(valor, validate=True)`; nombre con `PureWindowsPath(nombre).name` y luego `PurePosixPath(...).name`; envolver `ErrorAES`/`ErrorRSA` en `ErrorSobre` con mensaje en español; comparar hash con `hmac.compare_digest`; mismatch → `ErrorSobre("sobre alterado: el SHA-256 no coincide")`.
- [ ] **Step 5: Run** `.venv/bin/pytest -v` → todo PASS.
- [ ] **Step 6: Commit** (dos commits) `git add ejemplos && git commit -m "feat: archivos de ejemplo (2 textos, PNG y PDF)"` y `git add sobre_digital tests/test_sobre.py && git commit -m "feat: generador y lector del sobre digital"`

### Task 4: API Flask y main.py

**Files:**
- Create: `gui/__init__.py` (reexporta `crear_app`), `gui/app.py`, `gui/templates/index.html` (marcador mínimo `<h1>Sobre digital</h1>`; la página real es Task 5), `main.py`
- Test: `tests/test_gui.py`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `crear_app() -> Flask` y las rutas de la spec, exactamente:
  - `POST /api/claves` form `bits` → `{"privada_pem": str, "publica_pem": str, "bits": int, "tiempo_ms": int}`
  - `POST /api/crear` files `archivo`, `publica` → `{"nombre": "<orig>.sobre.json", "sobre_b64": str, "detalles": {"tamano_original", "tamano_cifrado", "iv_hex", "clave_cifrada_bytes", "sha256", "bits_rsa"}}`
  - `POST /api/abrir` files `sobre`, `privada` → `{"nombre": str, "archivo_b64": str, "detalles": {"tamano", "sha256", "bits_rsa"}}`
  - `POST /api/demo` form `bits` opcional (default 2048) → `{"bits": int, "resultados": [{"archivo", "tamano", "sha256_original", "sha256_recuperado", "ok", "iv_hex"}]}`
  - Errores: 400 `{"error": str}`; 413 `{"error": "archivo demasiado grande (máximo 32 MB)"}`; `MAX_CONTENT_LENGTH = 32 * 1024 * 1024`.

- [ ] **Step 1: Write the failing tests** en `tests/test_gui.py` (fixture `cliente` con `crear_app().test_client()`; fixture de módulo con PEMs 2048 obtenidos vía `/api/claves`):
  - `test_index`: `GET /` → 200, `"Sobre digital"` en el HTML.
  - `test_claves` parametrizado 2048/3072: PEMs cargan con `rsa_mod` y `key_size == bits`.
  - `test_claves_bits_invalidos` con `"1024"`, `"abc"` → 400 con `"error"`.
  - `test_crear_y_abrir` parametrizado sobre los 4 ejemplos: crear → abrir con el sobre devuelto → `b64decode(archivo_b64) == original`, nombre original, `detalles.sha256` correcto.
  - `test_crear_archivo_vacio`: 0 bytes → ida y vuelta OK.
  - `test_crear_sin_archivo` y `test_crear_sin_publica` → 400.
  - `test_crear_con_privada_en_lugar_de_publica` → 400 (no 500).
  - `test_abrir_con_publica_en_lugar_de_privada` → 400.
  - `test_abrir_llave_equivocada` (otro par) → 400 y el mensaje contiene `"clave"`.
  - `test_abrir_sobre_alterado` (cambiar `sha256_original`) → 400 y mensaje contiene `"alterado"`.
  - `test_abrir_no_json` → 400.
  - `test_clave_1024_rechazada`: pública de 1024 generada en la prueba → `/api/crear` 400.
  - `test_demo`: 200, 4 resultados, todos `ok` y `sha256_original == sha256_recuperado`.
  - `test_peticion_grande`: app con `MAX_CONTENT_LENGTH` real, archivo de 33 MB → 413 y `resp.is_json`.
  - `test_main_no_tiene_cli`: `main.py` no contiene `argparse` ni `sys.argv`.

- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_gui.py -v` → FAIL.
- [ ] **Step 3: Implement** `gui/app.py`: helper `_leer_archivo(campo) -> bytes` que lanza `_ErrorPeticion` (400) si falta o el nombre está vacío; `@app.errorhandler` para `_ErrorPeticion`, `ErrorRSA`, `ErrorSobre`, `ValueError` → 400 JSON y para `413` (`RequestEntityTooLarge`) → 413 JSON. `/api/demo` usa `DIR_EJEMPLOS` y `ARCHIVOS_EJEMPLO`. `main.py`: `crear_app().run(host="127.0.0.1", port=5000, debug=False)` precedido de `print("Abre http://127.0.0.1:5000 en tu navegador")`.
- [ ] **Step 4: Run** `.venv/bin/pytest -v` → todo PASS.
- [ ] **Step 5: Commit** `git add gui main.py tests/test_gui.py && git commit -m "feat: API web Flask para claves, crear, abrir y demo"`

### Task 5: Página web (`index.html`)

**Files:**
- Modify: `gui/templates/index.html`
- Test: `tests/test_gui.py` (añadir)

**Interfaces:**
- Consumes: rutas de Task 4 (nombres de campos exactos: `bits`, `archivo`, `publica`, `sobre`, `privada`).

- [ ] **Step 1: Write the failing test** `test_index_tiene_secciones`: el HTML de `GET /` contiene `id="form-claves"`, `id="form-crear"`, `id="form-abrir"`, `id="form-demo"`, `name="archivo"`, `name="publica"`, `name="sobre"`, `name="privada"`, `value="2048"`, `value="3072"`, y no contiene `<script src="http` (sin dependencias externas).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** una página en español, CSS y JS inline, 4 tarjetas: (1) Generar claves: selector 2048/3072 → botones para descargar `private_key.pem` y `public_key.pem` + tiempo; (2) Crear sobre: archivo + `public_key.pem` → descarga automática del `.sobre.json` + tabla de detalles; (3) Abrir sobre: sobre + `private_key.pem` → descarga del archivo recuperado + detalles (SHA-256 verificado); (4) Demo: botón → tabla con archivo, tamaño, SHA-256 original/recuperado abreviados y ✔/✘. Errores en un recuadro rojo dentro de la tarjeta; botón deshabilitado y texto "Procesando…" mientras espera. Helper JS `descargar(nombre, base64)` vía `Blob`/`URL.createObjectURL`. Un párrafo de cabecera explica el sobre digital (AES-256-CBC + RSA-OAEP-SHA256).
- [ ] **Step 4: Run** `.venv/bin/pytest -v` → PASS. Verificación manual: `.venv/bin/python main.py` en segundo plano, `curl -s 127.0.0.1:5000/ | head`, y `curl -s -X POST -F bits=2048 127.0.0.1:5000/api/demo` → 4 `"ok": true`; detener el servidor.
- [ ] **Step 5: Commit** `git add gui/templates/index.html tests/test_gui.py && git commit -m "feat: página web con generar claves, crear, abrir y demo"`

### Task 6: README, guía de pruebas y presentación

**Files:**
- Create: `README.md` (reemplaza el actual), `GUIA_PRUEBAS.txt`, `docs/presentacion.md`

- [ ] **Step 1: README.md**: descripción, requisitos criptográficos y dónde se cumple cada uno (archivo:función), instalación (`python3 -m venv .venv`, `.venv/bin/pip install -r requirements.txt`), uso (`python main.py` → abrir `http://127.0.0.1:5000`), recorrido de las 4 secciones, formato del sobre (tabla de campos), estructura del proyecto, cómo correr pruebas (`pytest`), limitaciones (sin MAC/firma, privada sin contraseña, solo local). Autor: Luis Fernando Franco Arellano.
- [ ] **Step 2: GUIA_PRUEBAS.txt**: pasos numerados en el navegador: generar claves 2048 y 3072; crear y abrir sobre de cada ejemplo y comparar con `sha256sum`; casos de error (llave equivocada, sobre alterado editando un carácter del `texto_cifrado`, pública en lugar de privada, archivo que no es sobre); demo; correr `pytest`. Cada paso con su resultado esperado.
- [ ] **Step 3: docs/presentacion.md**: guion de 5 minutos con tiempos (problema → AES-CBC + PKCS#7 → RSA-OAEP → formato del sobre → demo en vivo de 2 min → errores detectados → conclusiones/limitaciones).
- [ ] **Step 4: Verify**: todas las rutas y nombres de función mencionados existen (`grep`); `.venv/bin/pytest -q` sigue en PASS.
- [ ] **Step 5: Commit** `git add README.md GUIA_PRUEBAS.txt docs/presentacion.md && git commit -m "docs: README, guía de pruebas y guion de presentación"`

### Task 7: Reporte LaTeX y PDF

**Files:**
- Create: `docs/reporte.tex`, `docs/reporte.pdf`

- [ ] **Step 1: Evidencia real**: correr `.venv/bin/pytest -q` y `/api/demo` (con el cliente de pruebas de Flask desde un script en el scratchpad) y anotar conteos, tamaños, SHA-256 y tiempos de generación 2048/3072 reales.
- [ ] **Step 2: Escribir `docs/reporte.tex`** (`article`, `babel` spanish, `inputenc` utf8, `listings`, `hyperref`, `booktabs`): portada (Proyecto Final de Criptografía, Luis Fernando Franco Arellano, 317338601, 23 de noviembre de 2026), introducción, fundamentos (AES-256-CBC, IV, PKCS#7, RSA-OAEP con SHA-256/MGF1, sobre digital), diseño (estructura, formato del sobre, flujo crear/abrir con diagrama en `tabular` o lista), implementación (fragmentos clave de `cifrado_aes.py` y `cifrado_rsa.py`), interfaz web (rutas y secciones), pruebas (tabla requisito → prueba que lo verifica; resultados reales del Step 1), casos de error, limitaciones y mejoras, conclusiones, referencias (NIST SP 800-38A, RFC 8017, RFC 5652, documentación de `cryptography`).
- [ ] **Step 3: Compilar**: `cd docs && pdflatex -interaction=nonstopmode reporte.tex && pdflatex -interaction=nonstopmode reporte.tex` → sin errores (`grep -c "^!" reporte.log` = 0); `pdfinfo reporte.pdf` o `file` → PDF válido.
- [ ] **Step 4: Commit** `git add docs/reporte.tex docs/reporte.pdf && git commit -m "docs: reporte técnico en LaTeX y PDF"`
