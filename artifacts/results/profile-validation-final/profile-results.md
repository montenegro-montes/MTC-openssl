# Cierre de la fase de perfilado

Resultados exploratorios del 9 de septiembre de 2026 UTC (10 de septiembre en Madrid).

Esta fase conserva las variantes anteriores y añade controles RPK y tiempos por componente en una imagen independiente. Se completaron 30 muestras por cada uno de los diez escenarios, en dos series: **600 handshakes medidos**, además de 60 de calentamiento.

TLS 1.3, X25519 y TLS_AES_256_GCM_SHA384 constantes; autenticación clásica ECDSA P-256 o postcuántica ML-DSA-65. La etiqueta `pq` se refiere a la autenticación: el intercambio de claves de este experimento sigue siendo X25519. Lote de 16 hojas, sin reanudación, un cliente nuevo por muestra.

## Serie sin temporizadores detallados

Las columnas muestran medianas; CPU total es la mediana de la suma por conexión, no la suma de las medianas de cada extremo. Los bytes corresponden al transporte TLS durante el handshake, sin cabeceras de red. Las firmas ECDSA pueden variar ligeramente de tamaño.

| Escenario | Bytes TLS | Tiempo cliente (ms) | CPU cliente (ms) | CPU servidor (ms) | CPU total (ms) |
|---|---:|---:|---:|---:|---:|
| classic | 1215 | 0.791 | 0.503 | 0.276 | 0.773 |
| pq | 9572 | 1.710 | 0.802 | 1.082 | 1.862 |
| classic-mt | 1397 | 0.822 | 0.528 | 0.264 | 0.786 |
| pq-mt | 9754 | 1.539 | 0.804 | 0.887 | 1.671 |
| classic-compact-warm | 1160 | 1.543 | 1.316 | 0.253 | 1.576 |
| classic-compact-cold | 1288 | 1.617 | 1.385 | 0.258 | 1.654 |
| pq-compact-warm | 6281 | 2.147 | 1.423 | 0.761 | 2.188 |
| pq-compact-cold | 9648 | 2.252 | 1.667 | 0.899 | 2.660 |
| classic-rpk | 874 | 2.641 | 2.407 | 0.266 | 2.694 |
| pq-rpk | 5994 | 3.356 | 2.612 | 0.804 | 3.432 |

## Qué muestran los resultados

- PQ compacto warm: 6281 frente a 9572 bytes, **34,4 % menos**, con mayor tiempo y CPU total en esta ejecución.
- PQ compacto cold: 9648 bytes, **0,8 % más**. Transmitir la raíz firmada elimina el ahorro observado en warm.
- Añadir la prueba al certificado X509 completo (`-mt`) incrementa el tamaño. La reducción requiere la representación compacta.
- El control PQ RPK utiliza 5994 bytes. La credencial y prueba compactas warm añaden 287 bytes a ese control. RPK fija una clave local; no ofrece por sí mismo las mismas propiedades de identidad, vigencia y autorización de una PKI o del lote compacto.
- Los tiempos del control RPK corresponden al camino concreto de OpenSSL/TLSA utilizado. No establecen un límite inferior universal para RPK.

## Localización del coste

En la serie detallada, PQ compacto warm presenta estas medianas de tiempo de cliente:

| Componente | Tiempo (µs) |
|---|---:|
| credential_total | 964.062 |
| spki_encode | 956.250 |
| spki_hash | 2.229 |
| merkle_proof | 3.229 |

**Los tiempos son inclusivos y están anidados: no se suman.** La codificación SPKI domina el verificador compacto medido; el cálculo de la prueba Merkle es pequeño. Esto localiza el siguiente punto de optimización, pero esta fase no introduce caché ni optimizaciones y no demuestra todavía una mejora temporal.

La verificación de la firma de raíz warm ocurre antes del handshake y se registra en las columnas `root_signature_setup_*`; el tiempo del proceso cliente incluye esa preparación. El ahorro warm presupone que la raíz ya se distribuyó: su coste de distribución, almacenamiento, actualización y amortización queda fuera de los bytes del handshake.

## Efecto del perfilado

Comparación descriptiva de medianas de tiempo de cliente en bloques sucesivos; la variación combina instrumentación y ruido del entorno, por lo que no constituye una estimación causal aislada del coste de los temporizadores.

| Escenario | Sin detalle (ms) | Con detalle (ms) | Diferencia (%) |
|---|---:|---:|---:|
| classic | 0.791 | 0.783 | -1.0 |
| pq | 1.710 | 1.436 | -16.0 |
| classic-mt | 0.822 | 0.779 | -5.2 |
| pq-mt | 1.539 | 1.632 | +6.0 |
| classic-compact-warm | 1.543 | 1.518 | -1.6 |
| classic-compact-cold | 1.617 | 1.596 | -1.3 |
| pq-compact-warm | 2.147 | 2.263 | +5.4 |
| pq-compact-cold | 2.252 | 2.041 | -9.4 |
| classic-rpk | 2.641 | 2.614 | -1.0 |
| pq-rpk | 3.356 | 3.408 | +1.5 |

## Validación y reproducción

- 74 pruebas TLS de la nueva fase: escenarios positivos y rechazos por identidad, firma, prueba, vigencia, clave fijada errónea o ausente y fallback X509.
- Pruebas del estado de los temporizadores con AddressSanitizer y UndefinedBehaviorSanitizer: anidamiento, desequilibrio, reinicio y desactivación.
- Regresión de los ejecutables originales: 50 pruebas de la fase inicial, 66 de la compacta y parser con truncamientos, bytes sobrantes y 20 000 entradas deterministas.
- Las 600 muestras validan correlación cliente/servidor, tipo de certificado, ausencia de reanudación y coherencia de los tamaños. La serie detallada exige las llamadas esperadas a autenticación y CertificateVerify; la otra exige contadores de componentes desactivados.
- Verificación SHA-256: los 71 archivos anteriores incluidos en el inventario conservan su contenido.

- [Serie sin detalle](../artifacts/results/profile-detail0-20260909T220523884803Z/report.md): muestras, componentes, comparaciones e información del entorno en el mismo directorio.
- [Serie detallada](../artifacts/results/profile-detail1-20260909T220612112265Z/report.md).
- [Pruebas](../artifacts/results/profile-validation-final/tests.log), [regresión](../artifacts/results/profile-validation-final/regression.log), [bibliotecas utilizadas](../artifacts/results/profile-validation-final/library-routing.log) y [fuentes de la fase](../artifacts/results/profile-validation-final/source/).
- [Instrucciones de reproducción](../README.profile.md).

Imagen final: `sha256:c02badb91c814ac13ac0069a4b867d3160e549e31c9dc2bbc511aebfe3ef1e4c`.

Los directorios `profile-detail1-20260909T173740369312Z` y `profile-detail0-20260909T220102326514Z` se conservan como ejecuciones preliminares, anteriores a la corrección del rechazo de fallback del control RPK. No se usan en las tablas de cierre.

Estas medidas locales de Docker Desktop no justifican generalizaciones a otras máquinas o redes. Las comparaciones bootstrap por ronda están disponibles en los CSV; para conclusiones publicables sobre rendimiento faltan campañas independientes y condiciones de red controladas. Los contenedores de esta fase quedaron detenidos.
