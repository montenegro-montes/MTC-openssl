# TLS 1.3 con autenticación poscuántica y árboles de Merkle

Laboratorio reproducible para estudiar el coste temporal y el tamaño de distintas representaciones de autenticación en TLS 1.3. El proyecto compara certificados X.509, certificados poscuánticos, claves públicas sin certificado y dos construcciones experimentales basadas en árboles de Merkle.

El objetivo científico es determinar si Compact Merkle y MTC reducen los bytes de autenticación de certificados poscuánticos y cómo cambian los tiempos de conexión cuando se introducen latencia, ancho de banda limitado y pérdida de paquetes.

## Variantes evaluadas

La configuración controlada fija TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384`, autenticación exclusiva del servidor y ausencia de tickets o reanudación. Los certificados clásicos usan ECDSA con la curva P-256 y los certificados poscuánticos usan ML-DSA-65. En ambos casos, la CA y el servidor se generan con el algoritmo correspondiente.

| Elemento criptográfico | Configuración | Papel |
|---|---|---|
| Firma clásica de certificados | ECDSA P-256 | Firma de la CA, certificado del servidor y `CertificateVerify` clásico |
| Firma poscuántica de certificados | ML-DSA-65 | Firma de la CA, certificado del servidor y `CertificateVerify` poscuántico |
| Intercambio de claves TLS | X25519 | Acuerdo de la clave efímera de la conexión |
| Suite TLS 1.3 | `TLS_AES_256_GCM_SHA384` | Cifrado simétrico e integridad del canal |

X25519 no es el algoritmo de firma del certificado. Se mantiene igual en todas
las variantes para estudiar el coste de la autenticación sin introducir además
un cambio en el intercambio de claves.

| Familia | Escenario | Función |
|---|---|---|
| X.509 | `classic`, `pq` | Referencias clásica y poscuántica |
| RPK | `pq-rpk` | Control del coste de representar únicamente la clave pública |
| Compact Merkle | `pq-compact-warm`, `pq-compact-cold` | Credencial compacta y prueba Merkle, con confianza predistribuida o validada durante la conexión |
| MTC | `pq-mtc-experimental-landmark`, `pq-mtc-experimental-standalone` | Implementación experimental de Merkle Tree Certificates |

MTC se identifica siempre como **MTC-experimental** y tiene como objetivo `draft-ietf-plants-merkle-tree-certs-05`. Las comparaciones entre X.509, Compact y MTC son arquitectónicas; no implican que sus modelos de confianza y transparencia sean equivalentes.

## Estado experimental

| Fase | Estado | Finalidad |
|---|---|---|
| Laboratorio TLS/X.509/PQ/Merkle inicial | Implementado y validado | Integración funcional con OpenSSL `s_client` y `s_server` |
| Comparación controlada N=16 | Completada | Tamaño, wall time, CPU y costes de confianza |
| Escalado de población Merkle | Completada | Tamaños de árbol 1, 4, 16, 64, 256 y 1024 |
| Latencia controlada | Completada | RTT adicional de 0 a 200 ms |
| Ancho de banda limitado | Infraestructura preparada | Campaña manual independiente |
| Pérdida de paquetes | Infraestructura preparada | Campaña manual con fallos y timeouts contabilizados |
| Condiciones de red combinadas | Infraestructura preparada | Perfiles baseline, WAN, constrained y adverse |

Los resultados generados viven en `artifacts/results/` y están excluidos de Git por su tamaño y porque el árbol de artefactos contiene material criptográfico local. Cada campaña conserva commit, estado Git, imagen, entorno, hashes, configuración efectiva y evidencia de validación.

## Organización del repositorio

```text
.
├── campaigns/       campañas, análisis, validadores y documentación de ejecución
├── docker/          Dockerfiles, Compose y configuración de OpenSSL
├── artifacts/       certificados, claves, fixtures y resultados locales ignorados
├── compact/         credencial Compact Merkle
├── mtc/             implementación MTC-experimental
├── integration/     formato wire e integración Merkle con OpenSSL
├── profiling/       instrumentación temporal detallada
├── codigoOriginal/  código C, scripts Bash y prototipo MTC recibidos
├── tests/           pruebas de integración TLS
├── scripts/         automatización común
└── docs/            protocolo, metodología, resultados y laboratorio inicial
```

Los puntos de entrada de cada experimento están en [campaigns/](campaigns/README.md). Las imágenes y servicios disponibles se describen en [docker/](docker/README.md). La documentación del primer laboratorio se conserva en [docs/tls-merkle-laboratory.md](docs/tls-merkle-laboratory.md). `codigoOriginal/` se mantiene separado del desarrollo activo para conservar claramente la procedencia del código recibido.

## Requisitos para crear el laboratorio

- Git y Python 3 disponibles en el host.
- Docker Desktop o Docker Engine con Compose v2.
- Acceso a Internet durante la construcción inicial para descargar Debian,
  OpenSSL, liboqs y oqs-provider.
- Espacio suficiente para compilar y conservar la cadena de imágenes.
- En campañas de red, capacidad `NET_ADMIN` dentro de los contenedores. Los
  Compose ya declaran esta capacidad donde es necesaria.

Compruebe el entorno desde la raíz del repositorio:

```sh
git status --short
git rev-parse HEAD
python3 --version
docker version
docker compose version
docker info
```

## Creación inicial paso a paso

### Paso 1 — clonar y entrar en el proyecto

```sh
git clone https://github.com/montenegro-montes/MTC-openssl.git
cd MTC-openssl
```

Todos los comandos posteriores se ejecutan desde esta raíz. No ejecute los
Compose desde `docker/`, porque la documentación y los scripts toman la raíz
como directorio de trabajo.

### Paso 2 — crear los directorios locales

```sh
mkdir -p artifacts/results
```

`artifacts/` está ignorado por Git y contendrá claves privadas, certificados,
fixtures y resultados. No copie claves desde `codigoOriginal/` al historial.

### Paso 3 — construir la imagen base

```sh
docker compose -f docker/compose.yaml build
docker image inspect mt-tls-lab:local --format '{{.Id}}'
```

Esta etapa compila OpenSSL 3.5.8, liboqs 0.14.0, oqs-provider 0.10.0, las pruebas
C recibidas y la primera integración Merkle de `s_client`/`s_server`.

### Paso 4 — generar certificados y fixtures Merkle iniciales

```sh
docker compose -f docker/compose.yaml run --rm setup
find artifacts/certs artifacts/merkle -maxdepth 2 -type f -print
```

El generador utiliza `umask 077` y conserva directorios existentes. Para una
regeneración científica use un árbol de artefactos nuevo; no mezcle fixtures
regeneradas con resultados anteriores.

Para preparar un algoritmo de firma adicional, asigne un nombre nuevo al perfil
y pase el algoritmo junto con sus parámetros de OpenSSL:

```sh
docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile mldsa44 --algorithm ML-DSA-44

docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh \
  --profile ecdsa-p384 --algorithm EC \
  --pkeyopt ec_paramgen_curve:P-384 --digest sha384
```

`--pkeyopt` y `--sigopt` se pueden repetir; `--digest` y `--days` son
opcionales. El comando crea la CA autofirmada, el certificado de servidor, el
DER, `generation-parameters.txt` y la fixture Merkle bajo el mismo nombre. Use:

```sh
docker compose -f docker/compose.yaml run --rm setup \
  bash /opt/lab/generate-certs.sh --help
```

La disponibilidad del algoritmo depende de la imagen. Compruébela con
`openssl list -signature-algorithms` dentro de `mt-tls-lab:local`.
La generación de un perfil no lo añade automáticamente a `scenario.sh` ni a
las campañas congeladas; debe incorporarse en una campaña nueva para evitar
alterar las comparaciones existentes.

### Paso 5 — validar los cuatro escenarios iniciales

```sh
for SCENARIO in classic pq classic-mt pq-mt; do
  export SCENARIO
  docker compose -f docker/compose.yaml up -d --force-recreate server
  sleep 2
  docker compose -f docker/compose.yaml run --rm client
  docker compose -f docker/compose.yaml down
done
unset SCENARIO
```

Cada cliente debe completar TLS 1.3 y verificar el servidor. Los escenarios
`classic-mt` y `pq-mt` deben mostrar además la verificación Merkle esperada.
Si una iteración falla, ejecute `docker compose -f docker/compose.yaml down`
antes de diagnosticarla.

### Paso 6 — construir Compact Merkle y generar N=16

```sh
docker compose -f docker/compose.compact.yaml build
docker compose -f docker/compose.compact.yaml run --rm setup
test -f artifacts/compact/batch16/classic/manifest.json
test -f artifacts/compact/batch16/pq/manifest.json
```

### Paso 7 — construir profiling y MTC-experimental

```sh
docker compose -f docker/compose.profile.yaml build
docker compose -f docker/compose.mtc.yaml build
docker compose -f docker/compose.mtc.yaml run --rm setup
test -d artifacts/mtc/batch16-v2
```

Las imágenes dependen unas de otras; respete este orden. La generación MTC
produce material local que permanece bajo `artifacts/`.

### Paso 8 — construir y validar la imagen de medición

```sh
docker build -f docker/Dockerfile.paper \
  --build-arg BASE_IMAGE=mt-tls-mtc:local \
  -t mt-tls-paper:local .

docker run --rm --network none \
  -v "$PWD/artifacts:/work:ro" \
  mt-tls-paper:local sh /opt/paper/tests.sh
```

La salida válida termina con:

```text
ALL REGRESSION AND NEGATIVE TESTS PASS
```

No continúe con campañas si esta prueba falla.

### Paso 9 — construir la imagen con herramientas de red

```sh
docker build -f docker/Dockerfile.network -t mt-tls-network:latency .
docker run --rm --network none mt-tls-network:latency sh -c \
  'command -v tc && command -v ping && command -v nstat && command -v iperf3'
```

Esta última imagen añade herramientas de red sobre la imagen de medición; no
recompila OpenSSL.

### Paso 10 — elegir una campaña

Consulte [campaigns/](campaigns/README.md), respete el orden recomendado y use
el README específico. Cada campaña crea un directorio fechado independiente,
registra Git, imagen y hashes, y exige sus propios tests y gates.

La cadena de imágenes experimentales se construye por etapas:

```text
mt-tls-lab:local
  └── mt-tls-compact:local
      └── mt-tls-profile:local
          └── mt-tls-mtc:local
              └── mt-tls-paper:local
                  └── mt-tls-network:latency
```

No se deben mezclar resultados producidos por commits o imágenes distintas. Antes de lanzar una campaña, siga su README, cree un directorio nuevo bajo `artifacts/results/`, ejecute los tests y el preflight, y compruebe las condiciones efectivas de red. Los smoke tests se almacenan separados y no forman parte del análisis principal.

## Mediciones e interpretación

Las campañas distinguen:

- bytes de los mensajes TLS observados por los BIO instrumentados;
- tamaño de credenciales, pruebas, firmas y confianza predistribuida;
- tiempo de pared del handshake y del proceso cliente;
- CPU de cliente, servidor y preparación/validación de confianza;
- mediana por campaña y diferencias emparejadas por ronda;
- fallos, timeouts y contadores TCP cuando la campaña de red lo requiere.

Los bytes TLS no equivalen a bytes Ethernet/IP/TCP. Las retransmisiones solo se atribuyen a nivel de campaña cuando no existe una medición fiable por conexión. La inferencia final utiliza campañas independientes como unidad de bootstrap y conserva los outliers como observaciones.

## Documentación

- [Laboratorio TLS-Merkle inicial](docs/tls-merkle-laboratory.md)
- [Protocolo TLS-MT](docs/tls-mt.md)
- [Protocolo Compact Merkle](docs/compact-protocol.md)
- [Metodología MTC](docs/mtc-methodology.md)
- [Resultados MTC](docs/mtc-results.md)
- [Comparación MTC](docs/mtc-comparison.md)
- [Validación](docs/validation.md)

Este repositorio es un laboratorio de investigación. Las claves privadas y artefactos locales no deben publicarse ni incorporarse a commits.
