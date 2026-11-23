# Sobre digital: AES-256-CBC + RSA-OAEP

Proyecto Final de Criptografía. Autor: **Luis Fernando Franco Arellano**.

Un **sobre digital** (criptografía híbrida) protege un archivo de cualquier tipo: el contenido se cifra con
AES-256-CBC usando una clave de sesión aleatoria, y esa clave se cifra con la clave pública RSA del
destinatario mediante RSA-OAEP (SHA-256). Solo quien tiene la clave privada puede abrir el sobre, y un
SHA-256 del archivo original permite detectar alteraciones. Todo se usa desde una **interfaz web local**
hecha con Flask (el programa no tiene línea de comandos). Los algoritmos vienen de la biblioteca
`cryptography`; nada se implementa a mano.

## Requisitos criptográficos y dónde se cumplen

| Requisito | Dónde se cumple |
|---|---|
| AES-256-CBC | `aes/cifrado_aes.py`: `cifrar_aes`, `descifrar_aes` |
| Clave de sesión de 32 bytes con CSPRNG | `aes/generador_claves_aes.py`: `generar_clave_aes` (`secrets.token_bytes(32)`) |
| IV aleatorio de 16 bytes, nuevo en cada cifrado | `aes/generador_claves_aes.py`: `generar_iv` (`os.urandom(16)`), llamado dentro de `cifrar_aes` |
| Relleno PKCS#7 | `aes/cifrado_aes.py`: `padding.PKCS7(128)` en `cifrar_aes` y `descifrar_aes` |
| Archivos tratados como bytes (texto, PNG, PDF) | `sobre_digital/generador_sobre_digital.py`: `crear_sobre` recibe `bytes`; la GUI lee y escribe en binario |
| Clave de sesión cifrada con RSA-OAEP, SHA-256 y MGF1-SHA256 | `rsa_mod/cifrado_rsa.py`: `cifrar_clave_sesion`, `descifrar_clave_sesion` |
| RSA de 2048 o 3072 bits, e = 65537 | `rsa_mod/generador_claves_rsa.py`: `generar_par_rsa` |
| Claves de menos de 2048 bits rechazadas | `rsa_mod/generador_claves_rsa.py`: `cargar_privada_pem`, `cargar_publica_pem` |
| PEM separados `private_key.pem` (PKCS#8, sin contraseña) y `public_key.pem` (SubjectPublicKeyInfo) | `rsa_mod/generador_claves_rsa.py`: `privada_a_pem`, `publica_a_pem`, `guardar_par_rsa` |
| Integridad con SHA-256 del archivo original | `sobre_digital/generador_sobre_digital.py` (`crear_sobre`) y `sobre_digital/lector_sobre_digital.py` (`abrir_sobre`) |
| Interfaz 100 % web, sin CLI | `gui/app.py` (`crear_app`) y `main.py` (solo arranca el servidor) |

## Instalación

Requiere Python 3.12 o similar. Desde la carpeta del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Sin activar el entorno también sirve `.venv/bin/pip install -r requirements.txt`.

## Uso

```bash
python main.py
```

Abra **http://127.0.0.1:5000** en el navegador. El servidor escucha solo en `127.0.0.1`.

La página tiene cuatro tarjetas:

1. **Generar claves**: elija 2048 o 3072 bits y pulse *Generar claves*; descargue `private_key.pem` y `public_key.pem`.
2. **Crear sobre**: elija el archivo a proteger y `public_key.pem`; pulse *Crear sobre*. Se descarga `<nombre>.sobre.json` y se muestran tamaños, IV, SHA-256 y bits RSA.
3. **Abrir sobre**: elija el `.sobre.json` y `private_key.pem`; pulse *Abrir sobre*. Se descarga el archivo original y se muestra su SHA-256 con la marca de integridad verificada.
4. **Demo automática**: pulse *Ejecutar demo*; genera claves, crea y abre los 4 archivos de `ejemplos/` y compara los SHA-256 original y recuperado.

La guía paso a paso para probar todo está en `GUIA_PRUEBAS.txt`; el guion de la exposición, en `docs/presentacion.md`.

## Formato del sobre (`<nombre>.sobre.json`)

JSON en UTF-8 con estos campos:

| Campo | Contenido |
|---|---|
| `version` | Entero, actualmente `1` |
| `algoritmos` | Objeto con `simetrico` (`AES-256-CBC`), `padding` (`PKCS7`), `asimetrico` (`RSA-OAEP`), `hash` (`SHA-256`) y `mgf` (`MGF1-SHA256`) |
| `bits_rsa` | Tamaño de la clave pública usada (2048 o 3072) |
| `clave_cifrada` | Clave de sesión AES cifrada con RSA-OAEP, en base64 |
| `iv` | Vector de inicialización de 16 bytes, en base64 |
| `nombre_original` | Nombre base del archivo original |
| `sha256_original` | SHA-256 del archivo original, en hexadecimal |
| `texto_cifrado` | Contenido cifrado con AES-256-CBC, en base64 |

Al abrir, se valida: JSON de tipo objeto, versión y algoritmos soportados, campos presentes y de tipo correcto,
base64 válido, IV de 16 bytes, descifrado de la clave de sesión, relleno PKCS#7 válido y coincidencia del SHA-256.

## Estructura del proyecto

```text
main.py                       arranca la app Flask en 127.0.0.1:5000
requirements.txt              cryptography, Flask, pytest
pytest.ini                    configuración de pytest (pythonpath)
aes/                          generador_claves_aes.py, cifrado_aes.py
rsa_mod/                      generador_claves_rsa.py, cifrado_rsa.py
sobre_digital/                formato.py, generador_sobre_digital.py, lector_sobre_digital.py
gui/                          app.py (API Flask), templates/index.html (página)
ejemplos/                     mensaje1.txt, mensaje2.txt, imagen.png, documento.pdf, generar_ejemplos.py
tests/                        test_aes.py, test_rsa.py, test_sobre.py, test_gui.py
docs/                         presentacion.md (guion), diseño y plan en docs/superpowers/
GUIA_PRUEBAS.txt              pasos para probar desde el navegador
```

## Pruebas

```bash
pytest
```

Ejecuta las pruebas de AES, RSA, sobre digital y de la API web (`pytest.ini` ya configura la ruta de importación).

## Limitaciones

- **Sin MAC ni firma digital**: el SHA-256 va dentro del mismo sobre, así que detecta alteraciones accidentales o parciales, pero un atacante que modifique el sobre completo podría recalcularlo. No autentica al remitente.
- **Clave privada sin contraseña**: `private_key.pem` se guarda en PKCS#8 sin cifrar; quien obtenga el archivo puede abrir los sobres.
- **Solo local**: el servidor escucha en `127.0.0.1`, sin autenticación ni HTTPS; no está pensado para desplegarse en una red pública.
- Límite de 32 MB por petición; todo se procesa en memoria y no se guarda nada en el servidor.
