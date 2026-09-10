# Fase de perfilado TLS y control RPK

Esta fase añade una imagen y bibliotecas independientes: `mt-tls-profile:local`.
Conserva las fases [inicial](README.md) y [compacta](README.compact.md).

Compara los ocho escenarios anteriores y dos controles RPK con clave fijada
(`classic-rpk`, `pq-rpk`). El control fija localmente `server → SHA256(SPKI)`
mediante TLSA/DANE de OpenSSL, sin consultar DNS. No reproduce las propiedades
completas de una PKI, ni la caducidad y autorización de las credenciales compactas.
La verificación de `CertificateVerify` permanece activa.

## Ejecución

Requiere la imagen `mt-tls-compact:local` y los certificados y lote de 16 hojas
preparados en la fase anterior. No se regeneran ni sobrescriben esos datos.

```sh
docker compose -f docker/compose.profile.yaml build
PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml run --rm --no-deps client python3 /opt/profiling/test_tls.py
docker compose -f docker/compose.profile.yaml run --rm --no-deps client sh /opt/profiling/test_timer.sh

PROFILE_DETAIL=0 docker compose -f docker/compose.profile.yaml up -d --force-recreate --wait server
PROFILE_DETAIL=0 docker compose -f docker/compose.profile.yaml run --rm client python3 /opt/profiling/benchmark.py --runs 30

PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml up -d --force-recreate --wait server
PROFILE_DETAIL=1 docker compose -f docker/compose.profile.yaml run --rm client python3 /opt/profiling/benchmark.py --runs 30

docker compose -f docker/compose.profile.yaml down
```

Ambos extremos deben usar el mismo `PROFILE_DETAIL`. Cada ejecución crea un
directorio nuevo bajo `artifacts/results/`; no elimina resultados anteriores.
El ejecutable de esta fase es `/opt/profiling/openssl.sh`: su lanzador selecciona
las bibliotecas instrumentadas únicamente para ese proceso.

## Medidas e interpretación

- Tiempo de handshake y CPU de proceso en cliente y servidor. La suma de CPU
  corresponde a los dos extremos de la misma conexión; no es tiempo transcurrido.
- Correlación mediante el random público del ClientHello, sin añadir bytes TLS.
- Bytes en los BIO de transporte durante el handshake; no incluyen cabeceras
  Ethernet/IP/TCP ni retransmisiones. No son el tamaño de una captura de red.
- Tiempos inclusivos de procesamiento de certificado/RPK, autenticación,
  firma/verificación de CertificateVerify, construcción del certificado,
  validación de identidad, SPKI, prueba Merkle y firma de raíz.
  **No sumar categorías anidadas.**
- En modo warm, la firma de la raíz se verifica antes del handshake y se registra
  aparte. Cada muestra inicia un cliente nuevo: no implementa una caché persistente.
- 3 rondas de calentamiento y 30 rondas medidas, orden aleatorio reproducible.
  CSV de muestras, componentes, medianas y comparaciones con bootstrap por ronda.

`PROFILE_DETAIL=0` mantiene las medidas globales y desactiva los temporizadores
de componentes. Comparar las dos series ayuda a detectar perturbación, pero dos
bloques sucesivos en Docker Desktop no aíslan por sí solos el coste instrumental.
Son resultados exploratorios locales, sin emulación de latencia ni ancho de banda.

El informe de cierre se encuentra en [docs/profile-results.md](docs/profile-results.md).
