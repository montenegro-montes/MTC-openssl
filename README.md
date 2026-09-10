# TLS 1.3 con autenticación poscuántica y árboles de Merkle

Laboratorio reproducible para estudiar el coste temporal y el tamaño de distintas representaciones de autenticación en TLS 1.3. El proyecto compara certificados X.509, certificados poscuánticos, claves públicas sin certificado y dos construcciones experimentales basadas en árboles de Merkle.

El objetivo científico es determinar si Compact Merkle y MTC reducen los bytes de autenticación de certificados poscuánticos y cómo cambian los tiempos de conexión cuando se introducen latencia, ancho de banda limitado y pérdida de paquetes.

## Variantes evaluadas

La configuración controlada fija TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384`, autenticación exclusiva del servidor y ausencia de tickets o reanudación. La autenticación poscuántica utiliza ML-DSA-65; X25519 se conserva para no mezclar el efecto de la representación de certificados con un cambio del intercambio de claves.

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

## Inicio rápido

Los comandos se ejecutan desde la raíz del repositorio. Para construir y validar el laboratorio inicial:

```sh
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm setup
docker compose -f docker/compose.yaml up -d server
docker compose -f docker/compose.yaml run --rm client
docker compose -f docker/compose.yaml down
```

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
