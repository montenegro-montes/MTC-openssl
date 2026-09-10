# Resultados de cierre: MTC-experimental

Implementación basada en **draft-ietf-plants-merkle-tree-certs-05**, no en el Merkle experimental previo. Se completó un perfil limitado con certificados X509 MTC standalone y landmark, dos firmas de subárbol, checkpoint autenticado y señalización TLS. **No se afirma conformidad integral IETF.**

Campaña principal: N=16, doce escenarios, tres calentamientos y treinta rondas medidas, semilla 42: **360 handshakes medidos**. Escalado separado: N=1,4,16,64,256,1024, ocho escenarios y tres rondas medidas por tamaño: **144 handshakes medidos**. Se conserva también el smoke de tres rondas.

## Campaña principal

Valores medianos; los rangos y las comparaciones emparejadas con bootstrap 95 % están en los CSV. CPU total es la mediana de la suma por conexión. Los tiempos de setup previos al handshake se presentan aparte.

| Escenario | Bytes TLS | Tiempo cliente ms | CPU cliente ms | CPU total ms |
|---|---:|---:|---:|---:|
| classic | 1215 | 0.764 | 0.487 | 0.738 |
| pq | 9572 | 1.351 | 0.756 | 1.467 |
| classic-mt | 1397 | 0.796 | 0.502 | 0.761 |
| pq-mt | 9754 | 1.424 | 0.757 | 1.532 |
| classic-compact-warm | 1160 | 1.485 | 1.272 | 1.516 |
| classic-compact-cold | 1288 | 1.550 | 1.331 | 1.582 |
| pq-compact-warm | 6281 | 2.164 | 1.416 | 2.206 |
| pq-compact-cold | 9648 | 1.996 | 1.622 | 2.383 |
| classic-mtc-experimental-standalone | 1411 | 0.766 | 0.531 | 0.789 |
| classic-mtc-experimental-landmark | 1261 | 0.640 | 0.423 | 0.676 |
| pq-mtc-experimental-standalone | 13010 | 1.168 | 0.887 | 1.612 |
| pq-mtc-experimental-landmark | 6382 | 1.390 | 0.510 | 1.432 |

## Respuestas a las preguntas del estudio

1. **Ahorro frente a X509 ML-DSA-65:** este perfil landmark envía 6382 frente a 9572 bytes, un 33,3 % menos. Standalone envía 13010 bytes, un 35,9 % más. Son resultados del perfil MTC-experimental, no una medida universal de IETF MTC.
2. **Comparación con compacto:** compacto warm envía 6281 bytes, 101 menos que MTC landmark; compacto cold, 9648 frente a 13010 de MTC standalone. Los pares no son equivalentes: MTC conserva el contenedor X509 y standalone exige una cosignatura adicional; la referencia X509 no incluye CT.
3. **CPU y tiempos:** PQ MTC landmark consume una mediana de 0,510 ms de CPU cliente frente a 0,756 ms de X509; standalone, 0,887 ms. Compacto warm/cold consumen 1,416/1,622 ms. El tiempo de red/proceso no se deduce directamente de CPU: en esta campaña landmark tiene 1,390 ms de handshake frente a 1,351 ms de X509. Las diferencias no justifican una conclusión genérica de mayor o menor velocidad.
4. **Confianza predistribuida:** para PQ, authority.bin ocupa 3999 bytes de claves/política; trust.bin ocupa 10772 bytes, incluyendo esa base, checkpoint firmado y subárboles. El incremento es 6773 bytes. La carga standalone cuesta 0,827 ms por proceso; landmark, 1,197 ms, de los que 0,347 ms corresponden a validación del checkpoint. No incluye un protocolo de distribución remoto.
5. **Tamaño del árbol:** los tamaños medidos aparecen abajo. MTC usa subárboles de cobertura, y su prueba no tiene la misma codificación ni profundidad que el árbol compacto.
6. **Reutilización:** con una diferencia standalone–landmark de 6628 bytes por handshake, los 10772 bytes OOB completos se compensarían aritméticamente tras dos usos; también tras dos usos si se cuentan solo los 6773 incrementales. Esto presupone distribución una sola vez, mismo landmark y ninguna actualización. No se ha medido caché persistente ni amortización temporal: cada proceso vuelve a validar.
7. **Merkle frente a contenedor:** MTC landmark mantiene X509, por lo que su reducción no procede de eliminarlo, sino de trasladar firmas al estado compartido y sustituirlas por una prueba. Compacto elimina además campos X509. La diferencia neta de 101 bytes entre ambos protocolos no aísla únicamente el contenedor: también cambian pruebas y señalización.
8. **Funcionalidad PKI:** compacto tiene semántica mínima DNS/vigencia/serverAuth. El borrador MTC conserva el modelo X509 y logging. Este perfil implementa controles de hoja, un snapshot y cosigners locales, pero no rutas PKIX generales ni transparencia pública: no se le atribuye toda la funcionalidad del borrador.
9. **Equivalencia:** los pares son comparaciones arquitectónicas con controles criptográficos y de red comunes. No prueban que los modelos de confianza, revocación, publicación o disponibilidad sean equivalentes.

## Escalado exploratorio PQ

La columna de prueba compacta incluye su cabecera y raíz; la de MTC muestra el array de hashes y, entre paréntesis, MTCProof completo landmark. Son definiciones diferentes, indicadas explícitamente.

| N | Prueba compacta bytes | Prueba MTC hashes (codificada) | TLS compacto warm | TLS MTC landmark |
|---:|---:|---:|---:|---:|
| 1 | 45 | 0 (18) | 6153 | 6286 |
| 4 | 109 | 32 (50) | 6217 | 6318 |
| 16 | 173 | 96 (114) | 6281 | 6382 |
| 64 | 237 | 160 (178) | 6345 | 6447 |
| 256 | 301 | 224 (242) | 6409 | 6511 |
| 1024 | 365 | 288 (306) | 6473 | 6576 |

Las mediciones por familia, modo, CPU y setup están en scaling.csv y en sus seis campañas enlazadas. Las fórmulas teóricas figuran en columnas separadas; no sustituyen tamaños codificados reales. El setup de población se mide aparte y la instancia CA MTC cambia entre tamaños; claves de servidor y CA X509 se conservan. Tres rondas por punto solo permiten una exploración.

## Control RPK adicional

Se ejecutó una serie separada de treinta rondas con X509 y RPK en ambas familias: **120 handshakes medidos**. Sus comparaciones están emparejadas dentro de esa serie; no se mezclan tiempos con la campaña principal.

| Escenario | Bytes TLS | Tiempo cliente ms | CPU cliente ms |
|---|---:|---:|---:|
| classic | 1215 | 0.767 | 0.493 |
| pq | 9572 | 1.660 | 0.763 |
| classic-rpk | 873 | 2.555 | 2.346 |
| pq-rpk | 5994 | 3.386 | 2.521 |

[Datos y comparaciones RPK](../artifacts/results/mtc-20260910T050428651760Z/report.md). PQ RPK transmite 5994 bytes; la credencial compacta warm añade 287 bytes. Ese control fija la clave fuera de banda y no ofrece la semántica PKI de X509/MTC.

## Validación y archivos

- Vectores oficiales C.1, C.2 y C.4: correctos, con 12807 evaluaciones de inclusión en el generador Python.
- Verificador independiente: **104 casos correctos**, incluidos formatos, firmas, duplicados/orden de cosigners, clave e identidad CA equivocadas y checkpoint/landmark modificado.
- Parser C: AddressSanitizer y UndefinedBehaviorSanitizer, todos los truncamientos de una prueba PQ y **20000 entradas deterministas** sin aceptación indebida ni errores detectados.
- TLS: **70 casos correctos**, incluidos pruebas/firma alteradas, vigencia/purpose inválidos aun con firmas válidas, confianza equivocada, HRR, última hoja de otro subárbol y ausencia de fallback X509.
- Regresiones anteriores: **50 + 66 + 74 casos correctos** en sus ejecutables originales.
- Inventario previo: **5287 archivos sin cambios SHA-256**, incluyendo los resultados previos. Ningún archivo anterior fue modificado.

Archivos nuevos: `mtc/` (generador, verificador C, integración, pruebas y drivers), `docker/Dockerfile.mtc`, `docker/Dockerfile.mtc.dockerignore`, `docker/compose.mtc.yaml` y los cinco documentos `docs/mtc-*.md`. Los fixtures y claves nuevos están bajo artifacts/ y las claves no se incorporan a Git.

- [Campaña principal](../artifacts/results/mtc-20260910T050144616225Z/report.md): samples.csv, summary.csv, comparisons.csv, metadata.json y logs.
- [Escalado](../artifacts/results/mtc-scaling-20260910T050257177516Z/scaling.csv) y [manifiesto de sus ejecuciones](../artifacts/results/mtc-scaling-20260910T050257177516Z/manifest.json).
- [Reproducción](mtc-methodology.md), [protocolo y desviaciones](mtc-protocol.md), [comparación conceptual](mtc-comparison.md), [viabilidad previa](mtc-feasibility.md).

Imagen final: `sha256:3b0206b037528bc3e84e59d3bafeae34b9b5f4bf9f1e6100d0d3db5211acbd61`.

Quedan fuera: interoperabilidad externa, trust_anchors con código IANA y grupos/retry, log/monitor públicos, cosigners independientes, evolución/pruning y consistencia general de snapshots, revocación dinámica, validación PKIX MTC general, caché persistente y campañas de red/maquinaria independientes. No debe presentarse esta fase como una implementación íntegra del estándar ni extrapolar sus tiempos fuera de este laboratorio.

[Evidencias de validación y copia de fuentes](../artifacts/results/mtc-validation-20260910/), con logs, hashes de referencias y comprobación de preservación.
