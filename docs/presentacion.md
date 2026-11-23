# Sobre digital: AES-256-CBC + RSA-OAEP. Guion de exposición (5 minutos)

Autor: Luis Fernando Franco Arellano

Antes de empezar: servidor corriendo (`python main.py`), navegador en http://127.0.0.1:5000, una carpeta con
`ejemplos/` a mano y dos pares de claves ya generados (por si falla algo) en otra carpeta.

| Tiempo | Sección |
|---|---|
| 0:00 - 0:30 | 1. El problema |
| 0:30 - 1:15 | 2. AES-256-CBC con PKCS#7 |
| 1:15 - 1:50 | 3. RSA-OAEP |
| 1:50 - 2:25 | 4. Formato del sobre |
| 2:25 - 4:25 | 5. Demo en vivo (2 min) |
| 4:25 - 4:45 | 6. Errores detectados |
| 4:45 - 5:00 | 7. Conclusiones y limitaciones |

## 1. El problema (0:00 - 0:30)

- Quiero mandar un archivo (texto, imagen, PDF) a alguien de forma que solo esa persona lo lea.
- RSA solo puede cifrar mensajes pequeños y es lento; AES es rápido pero exige compartir una clave.
- Solución: el **sobre digital**, criptografía híbrida: AES cifra el archivo y RSA cifra la clave de AES.

*Notas del orador:* decir la analogía: el archivo va en una caja cerrada con candado (AES); la llave del candado
va en un sobre que solo el destinatario puede abrir (RSA).

## 2. AES-256-CBC con PKCS#7 (0:30 - 1:15)

- Clave de sesión de **32 bytes** con `secrets.token_bytes(32)` (`aes/generador_claves_aes.py`).
- **IV de 16 bytes nuevo** en cada cifrado con `os.urandom(16)`: el mismo archivo cifrado dos veces da resultados distintos.
- CBC trabaja por bloques de 16 bytes; **PKCS#7** rellena el último bloque (también añade un bloque completo si el archivo ya era múltiplo de 16).
- Todo se maneja como bytes: PNG y PDF se recuperan exactos (`aes/cifrado_aes.py`: `cifrar_aes`, `descifrar_aes`).

*Notas del orador:* mencionar que se usa la biblioteca `cryptography`, no hay AES hecho a mano. `ejemplos/mensaje2.txt`
mide un tamaño no múltiplo de 16 a propósito para ejercitar el relleno.

## 3. RSA-OAEP (1:15 - 1:50)

- Se cifra **solo la clave de sesión** (32 bytes) con la clave pública del destinatario (`rsa_mod/cifrado_rsa.py`: `cifrar_clave_sesion`).
- OAEP con **SHA-256** y **MGF1-SHA256**; es aleatorizado, por eso no usamos RSA "de libro".
- Claves de **2048 o 3072 bits**, e = 65537; menos de 2048 se rechaza (`rsa_mod/generador_claves_rsa.py`).
- Se guardan en dos PEM separados: `private_key.pem` (PKCS#8) y `public_key.pem` (SubjectPublicKeyInfo).

*Notas del orador:* la clave pública se comparte; la privada nunca sale de quien recibe.

## 4. Formato del sobre (1:50 - 2:25)

- Un archivo `<nombre>.sobre.json` con: `version`, `algoritmos`, `bits_rsa`, `clave_cifrada`, `iv`, `nombre_original`, `sha256_original` y `texto_cifrado` (binarios en base64).
- `sha256_original` permite comprobar al abrir que el archivo recuperado es idéntico.

*Notas del orador:* si hay proyector, mostrar un `.sobre.json` abierto en un editor (ya preparado) y señalar los campos.

## 5. Demo en vivo (2:25 - 4:25)

Guion minuto a minuto, sobre la página con sus 4 tarjetas:

1. (0:20) Tarjeta **1 Generar claves**: elegir "2048 bits", pulsar "Generar claves", descargar `private_key.pem` y `public_key.pem`. Señalar el tiempo en ms que muestra.
2. (0:30) Tarjeta **2 Crear sobre**: archivo `ejemplos/imagen.png` y `public_key.pem`; pulsar "Crear sobre". Mostrar la tabla: tamaño cifrado mayor que el original, IV, clave cifrada de 256 bytes, SHA-256.
3. (0:30) Tarjeta **3 Abrir sobre**: el `imagen.png.sobre.json` descargado y `private_key.pem`; pulsar "Abrir sobre". Mostrar "verificado" y abrir la imagen recuperada.
4. (0:20) Tarjeta **4 Demo automática**: pulsar "Ejecutar demo" y mostrar "4/4 archivos recuperados idénticos" con `mensaje1.txt`, `mensaje2.txt`, `imagen.png` y `documento.pdf`.
5. (0:20 de margen) Si sobra tiempo, comparar con `sha256sum ejemplos/imagen.png <descargado>`.

*Notas del orador:* si algo falla en vivo, usar el par de claves y el sobre ya preparados y pasar directo a la demo
automática. Mientras carga la generación de claves (puede tardar con 3072), seguir hablando del formato.

## 6. Errores detectados (4:25 - 4:45)

Mostrar uno o dos (con sobres ya preparados), cada uno aparece en un recuadro rojo:

- **Llave equivocada**: "no se pudo descifrar la clave de sesión: clave privada incorrecta o sobre alterado".
- **Sobre alterado** (un carácter cambiado en `texto_cifrado` o `sha256_original`): error "sobre alterado ...".
- Pública en lugar de privada: "el archivo no es una clave privada PEM válida".
- Archivo que no es un sobre: "el archivo no es un sobre digital válido (JSON UTF-8)".

*Notas del orador:* nada se descarga cuando hay error; el sistema falla de forma segura.

## 7. Conclusiones y limitaciones (4:45 - 5:00)

- Se cumple el sobre digital: AES-256-CBC + PKCS#7, IV nuevo, RSA-OAEP-SHA256, 2048/3072 bits, PEM separados, interfaz 100 % web y pruebas automáticas con `pytest`.
- Limitaciones: **sin MAC ni firma** (el SHA-256 detecta cambios accidentales, no autentica al remitente), **clave privada sin contraseña** y **solo local** (127.0.0.1).
- Mejora futura: AES-GCM o firma digital, y proteger la privada con contraseña.

*Notas del orador:* cerrar agradeciendo y abrir preguntas.
