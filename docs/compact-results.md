# Resultados exploratorios de la fase compacta — 2026-09-09

Serie controlada local Linux arm64 en Docker Desktop: 30 conexiones por escenario,
tres calentamientos excluidos, orden aleatorio con semilla 42, árboles de 16 hojas.
Mismo ejecutable instrumentado, X25519 y TLS_AES_256_GCM_SHA384, sin reanudación.

| Escenario | Bytes TLS totales (mediana) | Handshake ms | CPU cliente en handshake ms | Proceso + HTTP ms |
|---|---:|---:|---:|---:|
| classic | 1215 | 0.823 | 0.519 | 16.107 |
| pq | 9572 | 1.610 | 0.789 | 17.069 |
| classic-mt | 1397 | 0.812 | 0.520 | 16.295 |
| pq-mt | 9754 | 1.561 | 0.805 | 17.058 |
| classic-compact-warm | 1160 | 1.512 | 1.295 | 19.647 |
| classic-compact-cold | 1288 | 1.585 | 1.373 | 19.257 |
| pq-compact-warm | 6281 | 2.253 | 1.399 | 20.916 |
| pq-compact-cold | 9648 | 2.024 | 1.635 | 20.391 |

En esta implementación y entorno, el compacto warm poscuántico reduce el total
TLS en 3291 bytes (34,38 %) frente a X.509 ML-DSA-65, pero consume más CPU de cliente
y tarda más en completar el handshake. Cold aumenta el tráfico en 76 bytes (0,79 %).
Merkle adicional conserva el certificado y añade 182 bytes en la familia PQ.
Los tamaños ECDSA pueden variar por la codificación de la firma.

Diferencias emparejadas por ronda frente a X.509 PQ (valores positivos = más tiempo):

| Variante | Métrica | Mediana diferencia (ms) | Intervalo bootstrap 95 % (ms) |
|---|---|---:|---:|
| pq-compact-warm | handshake_wall_ms | 0.705 | [0.435, 0.878] |
| pq-compact-warm | handshake_client_cpu_ms | 0.623 | [0.582, 0.651] |
| pq-compact-cold | handshake_wall_ms | 0.450 | [0.189, 0.622] |
| pq-compact-cold | handshake_client_cpu_ms | 0.848 | [0.827, 0.859] |

La mediana de diferencias emparejadas no es necesariamente la diferencia entre
las medianas marginales de la primera tabla. Los intervalos son exploratorios
de esta ejecución, no una afirmación general ni un resultado ya validado para publicación.

La raíz firmada PQ ocupa 3399 bytes. Warm no la envía en cada handshake; verifica
su firma antes del intervalo cronometrado, en cada proceso nuevo. Ese trabajo
queda registrado en compact_setup_ms y en el tiempo total del proceso. No se ha
medido una caché persistente ni un servicio externo de distribución/renovación.
El coste bruto de distribuir ese objeto una vez para H conexiones sería 3399/H
bytes por conexión, además del transporte y la gestión de caché.
La firma TLS CertificateVerify y la clave pública PQ siguen transmitiéndose.

El resultado compara protocolos completos: también cambia de X.509 a RPK.
No demuestra que el hash Merkle por sí solo cause el sobrecoste temporal.
Un control RPK con clave individual precargada y perfiles por función permitirían
separar el coste de representación de clave, parser, política y prueba Merkle.

## Evidencia y reproducción

- [Muestras individuales](../artifacts/results/compact-20260909T162401146258Z/samples.csv)
- [Comparaciones e intervalos](../artifacts/results/compact-20260909T162401146258Z/comparisons.csv)
- [Metadatos y hashes](../artifacts/results/compact-20260909T162401146258Z/metadata.json)
- [Informe de ejecución](../artifacts/results/compact-20260909T162401146258Z/report.md)
- [Instrucciones](../README.compact.md) y [método](compact-methodology.md).

Los enlaces a artifacts apuntan a resultados locales excluidos de Git; este
documento conserva las cifras principales. Se conservaron las ejecuciones
preliminares en otros directorios, pero no se mezclaron con esta serie.
Para una réplica del paper hay que congelar imágenes y entradas públicas,
repetir en ejecuciones independientes y medir otras condiciones de red.

## Validación de implementación

- 66 comprobaciones TLS de la fase compacta y variantes instrumentadas superadas.
- 50 comprobaciones de regresión de la fase anterior superadas con sus binarios originales.
- Parser con AddressSanitizer/UBSan: truncaciones, bytes extra y 20000 entradas de fuzz deterministas.
- Rechazo de firma de raíz incorrecta, credencial/prueba alterada, identidad y clave incorrectas,
  expiración, propósito incorrecto, prueba ausente y fallback X.509. HelloRetryRequest comprobado.
- Las fases anteriores permanecen intactas; se verificaron los hashes de su inventario previo.
- No se ha realizado una auditoría formal de seguridad ni medido CPU del servidor.

Hash del paquete compacto usado: `e75e9ac4d30085f45b4ce7f05a30b6f1e670f2355b714b37263cc9a2a54bbb8b`.
