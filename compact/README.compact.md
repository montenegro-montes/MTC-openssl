# Fase 2: autenticación Merkle compacta y comparación TLS

Esta fase se añade a las anteriores. No reemplaza `docker/Dockerfile`, `docker/compose.yaml`,
`codigoOriginal/C/`, `codigoOriginal/Bash/`, `integration/`, `scripts/`, sus ejecutables ni sus resultados.
El [README original](README.md) conserva las instrucciones de las fases iniciales.

La variante compacta transmite una clave pública RPK y una credencial Merkle de
identidad/vigencia/clave. No transmite la cadena X.509. Mantiene TLS 1.3,
CertificateVerify y Finished. La autoridad firma una raíz por lote; se estudia
la raíz precargada y la raíz enviada durante cada handshake. Se trata de un
protocolo experimental de laboratorio, no de una implementación de un estándar
MTC ni de un reemplazo general de todas las funciones de una PKI X.509.

## Construcción y preparación

```sh
# Imagen original, necesaria como base (se conserva):
docker compose -f docker/compose.yaml build
# Solo si faltan certificados/árboles originales:
docker compose -f docker/compose.yaml run --rm setup

# Imagen independiente: mt-tls-compact:local
docker compose -f docker/compose.compact.yaml build
# Solo para un lote nuevo; no sobrescribe un lote existente:
docker compose -f docker/compose.compact.yaml run --rm setup
```

El último paso crea `artifacts/compact/batch16/`, con 16 certificados válidos por
familia y claves independientes para las 15 identidades adicionales. La hoja cero
usa exactamente el certificado y la clave del servidor de la fase anterior.
La misma población se utiliza para el árbol X.509 y el compacto. Los árboles
originales de dos hojas permanecen en `artifacts/merkle/`.

Para otro tamaño, usar un directorio nuevo:

```sh
docker compose -f docker/compose.compact.yaml run --rm setup \
  python3 /opt/compact/prepare.py --both --leaves 64 --output /work/compact/batch64
```

Admite entre 1 y 1024 hojas. Los ficheros de claves de laboratorio quedan en
`artifacts/`, excluidos de las imágenes y de Git. Los certificados originales
caducan a los 30 días; no se regeneran ni sustituyen automáticamente.

## Comparación

```sh
docker compose -f docker/compose.compact.yaml up -d --wait server
docker compose -f docker/compose.compact.yaml run --rm client
docker compose -f docker/compose.compact.yaml down
```

El servidor lanza ocho procesos s_server, uno por escenario. El cliente mide
30 conexiones por escenario tras tres conexiones de calentamiento; aleatoriza
el orden en cada ronda. Las conexiones atraviesan la red bridge de Docker entre
dos contenedores. No se publican puertos del laboratorio compacto en el host.

| Escenario | Autenticación | Raíz Merkle en la conexión |
|---|---|---|
| `classic` | X.509 ECDSA P-256 | No aplica |
| `pq` | X.509 ML-DSA-65 | No aplica |
| `classic-mt`, `pq-mt` | X.509 más Merkle, fase 1 | Precargada |
| `classic-compact-warm`, `pq-compact-warm` | RPK y credencial compacta | Precargada y validada antes del handshake |
| `classic-compact-cold`, `pq-compact-cold` | RPK y credencial compacta | Raíz firmada incluida y validada en el handshake |

Todos los escenarios de este banco nuevo usan **el mismo ejecutable instrumentado**
y las mismas bibliotecas, TLS 1.3, X25519 y TLS_AES_256_GCM_SHA384, sin reanudación.
La PKI tiene una CA directa; no se envía su certificado raíz durante TLS.
`classic-mt` y `pq-mt` usan aquí 16 hojas para igualar población con el compacto;
los comandos originales de `docker/compose.yaml` siguen usando sus árboles originales.

Para otro lote, pasar `COMPACT_BATCH` en ambos comandos:

```sh
COMPACT_BATCH=/work/compact/batch64 docker compose -f docker/compose.compact.yaml up -d --force-recreate --wait server
COMPACT_BATCH=/work/compact/batch64 docker compose -f docker/compose.compact.yaml run --rm client \
  python3 /opt/compact/benchmark.py --runs 60 --warmup 5 --seed 123
```

Cada ejecución crea un directorio nuevo en `artifacts/results/compact-<fecha>/`:

- `samples.csv`: muestras individuales, incluyendo bytes de Certificate y CertificateVerify.
- `summary.csv`: medianas y rangos por escenario.
- `comparisons.csv`: diferencias emparejadas por ronda e intervalos bootstrap del 95 %.
- `metadata.json`: versiones, hashes de código/entradas, recursos visibles y preparación del lote.
- `logs/`: salida individual de cada conexión, incluidos calentamientos.
- `report.md`: tabla de resultados exploratorios.

Un fallo de autenticación aborta la ejecución sin generar un resumen de éxito.
Se conservan los logs y las muestras válidas anteriores al fallo.

## Pruebas

Con certificados y lote preparados:

```sh
docker compose -f docker/compose.compact.yaml run --rm client \
  /opt/compact/test_parser /work/compact/batch16/pq/bundle-0000.bin
docker compose -f docker/compose.compact.yaml run --rm client python3 /opt/compact/test_tls.py
# Regresión de la fase anterior, con sus binarios originales:
docker compose -f docker/compose.compact.yaml run --rm client python3 /opt/mt/tests/test_tls.py
```

Los tests usan servidores temporales locales al contenedor y no necesitan el
servicio `server` arrancado. La serie comparativa sí usa los dos contenedores.

Detalles: [protocolo](docs/compact-protocol.md),
[método y límites de comparación](docs/compact-methodology.md).

Resultados de la ejecución inicial: [compact-results.md](docs/compact-results.md).
