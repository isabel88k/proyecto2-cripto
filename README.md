# Motor de Cifrado y Firma sobre Curvas Elípticas (ECC / ECDSA) en GF(p)

Proyecto 2 — Asignatura **ELC107 Criptografía y Seguridad** (UAGRM — FICCT, Grupo E).

Implementación académica en Python puro desde cero de aritmética de puntos sobre curvas elípticas finitas $y^2 = x^3 + ax + b \pmod p$, firma digital ECDSA con nonce determinista (RFC 6979), cifrado híbrido autenticado (ECDH + HKDF + AES-128-GCM + ECDSA), infraestructura de clave pública local (X.509 v3) y comparación de longitud de clave y rendimiento frente a RSA-PSS equivalente de 3072 bits.

## Requisitos e inicio rápido

Requiere **Python 3.10 o superior**. No necesita instalaciones con `pip` ni librerías criptográficas externas.

```bash
# Ayuda por consola (CLI)
python3 cripto.py --help

# Interfaz gráfica de escritorio (Tkinter)
python3 cripto_gui.py

# Ejecutar suite de pruebas unitarias (35 pruebas)
python3 scripts/run_tests.py

# Verificar que /src no importa librerías criptográficas de caja negra
python3 scripts/check_restrictions.py

# Demostración completa en consola y ataque de nonce repetido
python3 scripts/demo.py --output results/local-demo.txt
python3 scripts/nonce_attack.py

# Benchmark reproducible ECC P-256 frente a RSA-PSS-3072
python3 scripts/benchmark.py --rsa-bits 3072 --samples 15 --keygen-samples 3 --output results/local-benchmark.json
```

En Windows puede utilizarse `py -3` en lugar de `python3`. OpenSSL es opcional: solo se usa en las pruebas de interoperabilidad para contrastar firmas ECDSA, RSA-PSS y certificados X.509 de forma independiente.

## Módulos implementados desde cero (`src/ecc_engine/`)

| Archivo | Responsabilidad |
|---|---|
| `arithmetic.py` | Euclides extendido (`inverse_mod`), prueba de primalidad Miller-Rabin y generación de primos |
| `hashes.py` | SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231) y HKDF (RFC 5869) |
| `ecc.py` | Curva $y^2 = x^3 + ax + b \pmod p$, suma/doblado/infinito, multiplicación escalar, NIST P-256 y ECDH |
| `ecdsa.py` | Firma y verificación ECDSA P-256/SHA-256 con nonce determinista RFC 6979 |
| `aes.py`, `gcm.py` | AES-128 en $GF(2^8)$ y modo autenticado GCM con GHASH en $GF(2^{128})$ |
| `rsa.py` | Generación de claves RSA-3072 y RSASSA-PSS/SHA-256 con CRT y blinding para comparación |
| `der.py`, `pki.py` | Codificador/decodificador ASN.1 DER estricto y perfil X.509 v3 con CA raíz local |
| `hybrid.py` | Sobre autenticado ECDH + HKDF + AES-128-GCM + ECDSA (`low-S`) |
| `encoding.py` | Validación estricta, límites de entrada, permisos `0600`, escritura `O_EXCL` y limpieza de búferes mutables |
| `cli.py`, `gui.py` | Interfaz por consola (`cripto.py`) e interfaz gráfica simplificada Tkinter (`cripto_gui.py`) |

Ningún módulo en `/src` importa `hashlib`, `hmac`, `cryptography`, `PyCryptodome`, `ssl` ni paquetes equivalentes. `secrets` aporta únicamente entropía del sistema operativo y `compare_digest`.

## Flujo básico por consola

Crear una carpeta temporal fuera de `src/` para probar sin mezclar archivos ni claves privadas:

```bash
mkdir prueba_local && cd prueba_local
python3 ../cripto.py keygen --prefix alicia --purpose sign
python3 ../cripto.py keygen --prefix bob --purpose exchange
printf "Mensaje de prueba ELC107\n" > mensaje.txt

# Firma y verificación ECDSA
python3 ../cripto.py sign --key alicia.private.json --input mensaje.txt --output firma.json
python3 ../cripto.py verify --public alicia.public.json --input mensaje.txt --signature firma.json

# Cifrado híbrido autenticado
python3 ../cripto.py encrypt --recipient bob.public.json --sign-key alicia.private.json --input mensaje.txt --output sobre.json --aad ELC107
python3 ../cripto.py decrypt --key bob.private.json --sender alicia.public.json --input sobre.json --output recuperado.txt
```

Para el flujo completo con certificados X.509 y pruebas de alteración, consultar [MANUAL_DESPLIEGUE.md](MANUAL_DESPLIEGUE.md).

## Límites de seguridad declarados

Proyecto académico con fines didácticos, no apto para producción. Python puro no garantiza ejecución en tiempo constante frente a canales laterales ni borrado garantizado de objetos inmutables (`int`/`bytes`) en memoria; se aplica borrado de mejor esfuerzo sobre búferes `bytearray`, permisos `0600` y escritura exclusiva `O_EXCL`. La PKI local valida un perfil X.509 v3 acotado (CA raíz y hoja) sin revocación CRL/OCSP ni cadenas intermedias.
