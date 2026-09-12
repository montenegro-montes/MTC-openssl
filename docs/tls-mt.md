# Comprobación Merkle en TLS 1.3: primera etapa

Implementada en `src/integration/`, sin modificar los fuentes recibidos de `codigoOriginal/C/`.
El parche añade `-merkle_root` a s_client y `-merkle_proof` a s_server de OpenSSL
3.5.8. Se aplica al construir la imagen; falla si los puntos de inserción no
coinciden. El ejecutable original sigue en `/opt/openssl/bin/openssl`; el
experimental está en `/opt/openssl-mt/bin/openssl`. Ambos usan las mismas
bibliotecas y proveedores. Los fuentes parcheados quedan en `/opt/src/openssl`.

## Protocolo experimental

1. Fuera del handshake, `mt_bundle` carga certificados PEM/DER en el orden de
   argumentos, convierte a DER y genera raíz y pruebas usando el código original.
2. El cliente carga un archivo local de raíz de confianza. Ese archivo se
   distribuye por un canal confiable independiente; no se acepta una raíz por
   el mero hecho de recibirla del servidor.
3. ClientHello ofrece la extensión privada `0xffa5` con un byte de versión `01`.
4. Si la recibe, el servidor añade su prueba únicamente a la entrada hoja del
   mensaje Certificate. Un cliente normal recibe TLS normal sin la extensión.
5. El cliente valida estructura, identificador de raíz, tamaño del árbol y
   pertenencia del DER recibido. Una prueba ausente o incorrecta aborta TLS.
6. Se conserva la verificación X.509 de cadena, identidad y vigencia, además de
   CertificateVerify y Finished. La posesión de clave sigue siendo obligatoria.

El verificador `mt_proof_verify` reutiliza las funciones hash originales y añade
validación de la forma del árbol y de los nodos duplicados.

La implementación usa `SSL_CTX_add_custom_ext()` y un callback de verificación
que no permite ignorar errores X.509. No cambia `libssl` ni el formato X.509.
La prueba forma parte del transcript TLS. El cliente requiere explícitamente
`-verify_hostname` o `-verify_ip`; SNI por sí solo no es comprobación de identidad.

En modo Merkle se fuerza TLS 1.3, sin tickets ni caché de sesiones. Se rechazan
PSK, sesiones de entrada, reanudación por `-reconnect`, modo interactivo avanzado,
early data, raw public keys del servidor, DANE, QUIC y versiones anteriores. El servidor
experimental admite un único contexto de certificado. No se implementa
comprobación Merkle de certificados de cliente.

## Formato binario v1

Enteros de 32 bits en orden de red. SHA-256, prefijo `00` para hojas y `01` para
padres, duplicación del último nodo cuando un nivel tiene ancho impar.

Archivo de raíz (40 bytes):

| Campo | Bytes |
|---|---:|
| Magic/version ASCII `MTR1` | 4 |
| Número de hojas | 4 |
| Raíz SHA-256 | 32 |

Archivo de prueba / payload de extensión (45 + 32 × profundidad bytes):

| Campo | Bytes |
|---|---:|
| Magic/version ASCII `MTP1` | 4 |
| Número de hojas | 4 |
| Índice de hoja, desde cero | 4 |
| Identificador del árbol: raíz SHA-256 | 32 |
| Profundidad | 1 |
| Hashes hermanos, de hoja a raíz | 32 por nivel |

El índice determina izquierda/derecha: no se serializa el `bool` de C. No se
serializan punteros, padding ni estructuras de memoria. Se exige longitud exacta,
profundidad correspondiente al número de hojas e índice dentro del rango. En
niveles impares se comprueba que el hermano duplicado sea el nodo actual. El
número de hojas también debe coincidir con el archivo confiable, para distinguir
formas de árbol que la duplicación podría hacer ambiguas.

Límite del formato: 1.048.576 hojas, profundidad 20 y payload máximo 685 bytes.
El generador offline limita a 1.024 certificados por su coste de generar todas
las pruebas. No existe firma, fecha ni revocación de la raíz en este formato:
la confianza depende del archivo local; X.509 sigue verificando sus propios
certificados. Es un protocolo de laboratorio, no un estándar interoperable.

## Generación y ejecución

```sh
docker compose -f docker/original_campaigns/compose.yaml build
docker compose -f docker/original_campaigns/compose.yaml run --rm setup
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml up -d --force-recreate server
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml run --rm client
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/lab/benchmark.py --runs 30
docker compose -f docker/original_campaigns/compose.yaml down
```

Esperar a que el servidor escuche (`docker compose -f docker/original_campaigns/compose.yaml logs server`) antes del
cliente. `classic-mt` usa los mismos certificados que `classic`; `pq-mt` los
mismos que `pq`. Las variantes Merkle agregan una comprobación a X.509.

Setup genera `artifacts/merkle/{classic,pq}/root.bin` y `proof-0000.bin` para
el servidor. La segunda hoja del pequeño árbol de demostración es el DER de
la CA; incluirlo no autentica la raíz. Los directorios existentes se conservan;
al renovar certificados hay que generar un nuevo bundle concordante.

Para un conjunto propio, el primer certificado corresponde a `proof-0000.bin`:

```sh
docker compose -f docker/original_campaigns/compose.yaml run --rm client /opt/mt/bin/mt_bundle /work/merkle/mi-lote \
  /work/certs/classic/server.pem /work/certs/pq/server.pem
```

El destino debe ser nuevo. Si la generación falla, cualquier salida parcial no
es válida. Para probar un bundle distinto se pueden pasar `-e MERKLE_ROOT=...` al
cliente o `-e MERKLE_PROOF=...` al servidor ejecutados con `docker compose -f docker/original_campaigns/compose.yaml run`.
Las opciones nativas también están disponibles al invocar directamente
`/opt/openssl-mt/bin/openssl s_client` o `s_server` en el contenedor.

## Pruebas

```sh
docker compose -f docker/original_campaigns/compose.yaml run --rm client /opt/mt/bin/test_wire
docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/mt/tests/test_tls.py
```

`test_wire` se compila con AddressSanitizer y UndefinedBehaviorSanitizer y se
ejecuta también durante el build. Prueba 153 rutas válidas en árboles de 1 a 17
hojas, compatibilidad con las pruebas originales, mutaciones de todos los bytes,
truncaciones, bytes sobrantes, índices y raíces incorrectos.

Las pruebas TLS ejecutan conexiones reales, con fixtures temporales y los
certificados generados por setup. Incluyen ECDSA y ML-DSA, prueba ausente,
hermanos alterados, hoja equivocada, CA/hostname incorrectos y expiración.
`extension_server.c` es un peer exclusivo de pruebas que envía payloads
malformados para comprobar el rechazo del cliente por red. No participa en
los escenarios ni evita la validación del servidor normal.

## Etapa siguiente: reducción de bytes

Esta etapa sigue enviando el certificado completo y añade la prueba: **aumenta
el tráfico**. Los escenarios deben rotularse X.509 + Merkle, no como certificados
Merkle compactos. El medidor conserva el tiempo total de proceso/HTTP, no mide
tiempo puro de handshake; registra el hash del parche y del archivo de raíz.

Para reducir tamaño falta definir un objeto compacto de identidad, clave pública,
vigencia y restricciones, autoridad/firmas de lotes, distribución y renovación
de raíces, y política de caché/revocación. Ese cambio requerirá revisar el
procesamiento de autenticación de `ssl/statem/`, manteniendo la vinculación de
clave y transcript. Se deberá medir por separado la distribución de raíces con
y sin caché, la construcción del árbol y el coste de cada conexión.

Referencia de API: documentación incluida en OpenSSL 3.5.8,
`doc/man3/SSL_extension_supported.pod` y `doc/man3/SSL_CTX_set_verify.pod`.
