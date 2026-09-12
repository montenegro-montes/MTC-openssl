# Laboratorio TLS y árboles de Merkle

Entorno inicial para comparar TLS 1.3 con autenticación X.509 clásica y
poscuántica, con una variante experimental que añade comprobación Merkle. El código recibido en `codigoOriginal/C/`
y `codigoOriginal/Bash/` se conserva. **La comprobación Merkle ya está integrada en TLS 1.3, además de X.509.
Todavía no sustituye certificados ni reduce los bytes transmitidos.**

## Entorno

Docker Desktop/Engine con Compose. La imagen compila OpenSSL 3.5.8 LTS,
liboqs 0.14.0 y oqs-provider 0.10.0. Los fuentes de OpenSSL quedan disponibles en
`/opt/src/openssl`, incluidos `apps/s_client.c`, `apps/s_server.c` y `ssl/`.
Se guardan los commits de los tres proyectos en la imagen. Las versiones están
fijadas por etiquetas; la base Debian y los paquetes apt no están congelados por
digest/versiones, por lo que esto no garantiza builds idénticos bit a bit.

OpenSSL >=3.5 proporciona ML-DSA y ML-KEM de forma nativa; OQS desactiva sus
implementaciones duplicadas. Instalar OQS no significa que ML-DSA use ese
proveedor: en estas pruebas usa el proveedor `default`.
Fuentes: [OpenSSL](https://openssl-library.org/source/),
[OQS](https://github.com/open-quantum-safe/oqs-provider),
[versiones OQS](https://openquantumsafe.org/applications/tls.html).

## Ejecución

```sh
docker compose -f docker/original_campaigns/compose.yaml build
docker compose -f docker/original_campaigns/compose.yaml run --rm setup
docker compose -f docker/original_campaigns/compose.yaml up -d server
docker compose -f docker/original_campaigns/compose.yaml run --rm client
# Repeticiones clásicas (servidor ya arrancado):
docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/lab/benchmark.py --runs 30
# Cambiar servidor y cliente a certificados ML-DSA-65:
SCENARIO=pq docker compose -f docker/original_campaigns/compose.yaml up -d --force-recreate server
SCENARIO=pq docker compose -f docker/original_campaigns/compose.yaml run --rm client
SCENARIO=pq docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/lab/benchmark.py --runs 30
docker compose -f docker/original_campaigns/compose.yaml down
```

Esperar al mensaje de escucha del servidor (`docker compose -f docker/original_campaigns/compose.yaml logs server`) antes
de lanzar el cliente. El puerto se publica solo en `127.0.0.1:4433`. Los servicios
usan una misma imagen en contenedores separados. `artifacts/` contiene claves
locales de laboratorio, certificados y resultados; no se incluye en la imagen ni
en nuevos archivos Git. Setup conserva directorios de certificados existentes;
los certificados caducan a los 30 días. Para regenerar, guardar el directorio
anterior con otro nombre antes de ejecutar setup.

La CA se distribuye al cliente fuera de TLS; el servidor envía solo el certificado
hoja. Se verifican cadena, hostname y errores. No hay autenticación de cliente.
En ambos escenarios se fija TLS 1.3, X25519, TLS_AES_256_GCM_SHA384 y sin tickets.
`pq` estudia **autenticación poscuántica con intercambio clásico**, no TLS
íntegramente poscuántico. Para un experimento adicional, establecer
`GROUPS_TLS=X25519MLKEM768` tanto al recrear el servidor como al lanzar el cliente.
No mezclar ese cambio con el efecto de los certificados en la comparación base.

## Mediciones

`artifacts/results/<fecha>-<escenario>/` contiene CSV, logs y versiones.
El tiempo es el del proceso cliente completo (arranque, conexión, handshake,
petición HTTP y cierre), **no tiempo puro de handshake**. Los bytes son los
contadores de handshake que imprime s_client, no bytes Ethernet/IP/TCP ni tamaño
exclusivo del mensaje Certificate. El tamaño DER corresponde solo a la hoja.
Una muestra con fallo aborta; los logs permiten comprobar protocolo y algoritmos.
Para el estudio final: instrumentar el handshake, separar calentamiento, alternar
el orden de escenarios, registrar CPU/arquitectura y recursos Docker, y capturar
tráfico si se necesitan tamaños sobre la red. No inferir resultados científicos
con una única ejecución.

## Código Merkle recibido

```sh
docker compose -f docker/original_campaigns/compose.yaml run --rm client /opt/mt/bin/merkle_tests
docker compose -f docker/original_campaigns/compose.yaml run --rm client /opt/mt/bin/merkle_mtc_tests /work/certs/classic
```

Los ejecutables se recompilan para Linux; los binarios macOS originales no se
copian. Son demostraciones: algunos retornos originales no reflejan errores
(por ejemplo `mtc_tests` devuelve 1 al tener éxito). No son una suite automatizada
fiable por su código de salida.

## X.509 + comprobación Merkle

```sh
# Setup también genera raíces y pruebas conservando los certificados existentes.
docker compose -f docker/original_campaigns/compose.yaml run --rm setup
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml up -d --force-recreate server
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml run --rm client
SCENARIO=pq-mt docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/lab/benchmark.py --runs 30
docker compose -f docker/original_campaigns/compose.yaml down
# Tests (no necesitan un servicio server arrancado):
docker compose -f docker/original_campaigns/compose.yaml run --rm client /opt/mt/bin/test_wire
docker compose -f docker/original_campaigns/compose.yaml run --rm client python3 /opt/mt/tests/test_tls.py
```

Usar `classic-mt` para ECDSA + Merkle. Esperar al servidor antes de lanzar el
cliente. El cliente debe completar la conexión y mostrar `Merkle verification:
OK (X.509 also required)`. Una prueba ausente o incorrecta aborta el handshake.

Se mantienen dos ejecutables: `/opt/openssl/bin/openssl` original y
`/opt/openssl-mt/bin/openssl` con `s_client -merkle_root` y
`s_server -merkle_proof`. El cliente Merkle exige `-verify_hostname` o
`-verify_ip`, además de una CA válida y la raíz configurada fuera de banda.

Consultar [protocolo, formato y límites de TLS-MT](tls-mt.md).
Esta primera etapa mide el sobrecoste de añadir Merkle; la representación compacta
que permita ahorrar bytes sigue pendiente.
