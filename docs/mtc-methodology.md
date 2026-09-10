# Metodología MTC-experimental

Referencia: `draft-ietf-plants-merkle-tree-certs-05`; dependencia TLS fijada en
`draft-ietf-tls-trust-anchor-ids-04`. La [descripción del protocolo](mtc-protocol.md)
y la [tabla de viabilidad](mtc-feasibility.md) enumeran los límites del perfil.
La señalización usa 0xffa7 privado y coincidencia exacta; no implementa grupos,
reintentos ni interoperabilidad con una implementación IETF externa.

## Reproducción

Requiere las imágenes previas y los certificados/lote compacto de 16 hojas.
Todos los resultados se crean en directorios nuevos. No repetir setup sobre un
directorio existente: usar `--output` y `MTC_BATCH` para seleccionar otro.

```sh
docker compose -f docker/compose.mtc.yaml build
docker compose -f docker/compose.mtc.yaml run --rm setup

docker compose -f docker/compose.mtc.yaml run --rm --no-deps client sh /opt/mtc/test_verifier.sh
docker compose -f docker/compose.mtc.yaml run --rm --no-deps client python3 /opt/mtc/test_tls.py

docker compose -f docker/compose.mtc.yaml up -d --wait server
docker compose -f docker/compose.mtc.yaml run --rm client python3 /opt/mtc/benchmark.py --runs 3
```

Para la campaña, obtener `docker image inspect mt-tls-mtc:local --format '{{.Id}}'`
y pasar el valor literal como `--image-id`:

```sh
docker compose -f docker/compose.mtc.yaml run --rm client python3 /opt/mtc/benchmark.py --runs 30 --image-id sha256:VALOR
docker compose -f docker/compose.mtc.yaml down
```

`--scenarios` permite filtrar escenarios. La matriz por defecto tiene doce:
las ocho variantes anteriores y las cuatro `classic/pq-mtc-experimental-standalone/landmark`.
Los controles RPK anteriores también están disponibles como selección opcional.

## Controles y métricas

La base instrumentada es la misma para todos los escenarios de esta campaña.
Se mantiene TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, sin tickets/reanudación,
misma red bridge Docker y procesos de servidor persistentes. No se introduce ML-KEM.
ECDSA P-256 y ML-DSA-65 mantienen continuidad con el laboratorio y no se consideran
niveles nominales de seguridad equivalentes.

Tres rondas de calentamiento, treinta medidas, semilla 42. Cada ronda baraja todos
los escenarios seleccionados. Cada observación registra ronda y orden. Los extremos
se correlacionan mediante ClientHello random y se comprueban tipo de certificado,
CertificateVerify, tamaños y éxito de autenticación antes de aceptar la muestra.

`handshake_wall_ms` mide desde INFO START hasta DONE en cliente. La CPU es CPU de
proceso, por extremo; su suma no es tiempo transcurrido. `client_process_http_wall_ms`
incluye creación del proceso, configuración, handshake y HTTP. Los temporizadores
detallados previos están desactivados. Los temporizadores específicos MTC de setup
y callback siguen activos; su sobrecoste no se ha aislado en esta campaña.

Los bytes de transporte corresponden a los BIO TLS, sin cabeceras TCP/IP ni
retransmisiones. Certificate, CertificateVerify y EncryptedExtensions incluyen
cabecera de mensaje handshake. Los campos `mtc_certificate_bytes` y `mtc_tbs_bytes`
son DER; las firmas y el array de hashes se cuentan como payload. El tamaño total
codificado de MTCProof se registra aparte. El checkpoint no viaja en Certificate:
`mtc_checkpoint_bytes` en TLS es cero. Los doce bytes start/end se registran como
referencia de subárbol; el número de landmark se anuncia en TLS, no en MTCProof.

Standalone carga `authority.bin`: claves y política, sin checkpoint. Landmark
carga `trust.bin`, verifica checkpoint y reconstruye su cobertura antes de TLS.
Se registra tamaño de archivo OOB, tiempo de carga y tiempo de validación. La
configuración se vuelve a cargar en cada proceso; no se mide una caché persistente.
Los bytes OOB no incluyen un protocolo de distribución remoto. Cualquier umbral
de reutilización calculado es aritmético, no una amortización observada.

Se publican medianas, mínimos/máximos, diferencia mediana emparejada por ronda,
porcentaje de diferencia en bytes e intervalo bootstrap de 2000 remuestreos.
No se realizan pruebas de significación. Estos intervalos no sustituyen campañas
independientes ni cubren variabilidad de máquinas o redes.

## Escalado

```sh
docker compose -f docker/compose.mtc.yaml run --rm setup python3 /opt/mtc/prepare_scaling.py --output /work/mtc/scaling-NUEVO
python3 mtc/run_scaling.py --fixtures /work/mtc/scaling-NUEVO --runs 3
```

Genera N=1,4,16,64,256,1024. Las primeras 16 identidades conservan las claves del
lote original; el resto se genera una vez y se comparte entre tamaños y esquemas.
Cada tamaño crea una instancia CA MTC independiente, con claves nuevas de los
mismos algoritmos; su generación está incluida en setup. Las claves servidor y
la CA X509 se mantienen fijas. Las pruebas codificadas, payload de hashes y
predicciones teóricas se almacenan en columnas distintas. Las predicciones MTC
son específicas de la hoja 0, snapshots iniciales y tamaños potencia de dos;
no son una fórmula universal para todos los certificados MTC.

La campaña de escalado de tres rondas es exploratoria. Puede ampliarse con
`--runs 30`; no debe combinarse con la campaña principal como si fuera una única
población estadística. No ejecutar preparación de claves ni otras cargas durante
las mediciones que se quieran comparar.
