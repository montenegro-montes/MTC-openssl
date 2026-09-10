# Viabilidad: MTC -05 sobre OpenSSL 3.5.8

Análisis previo a la implementación, 10 de septiembre de 2026. Base preservada:
`v0.3.0-profile` (`dc152ad`). Inventario SHA-256: `mtc/preservation.json`.
Se inspeccionaron las fases original, compacta y de perfilado, sus generadores,
verificadores, métricas y el código real de OpenSSL dentro de la imagen.

Referencias fijadas: [MTC -05](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.txt)
y su dependencia [trust-anchor-ids -04](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-04.txt).
No se sustituye la versión solicitada por una revisión posterior.

OpenSSL no implementa MTC ni `trust_anchors`. Sí procesa Certificate X509,
CertificateVerify, Finished y extensiones TLS personalizadas. La fase compacta
usa RPK y otro formato: no se reutilizará como si fuera MTC.

| Draft feature | Required by draft | OpenSSL support | Implementation plan | Exact / Approximation |
|---|---|---|---|---|
| Issuance log | §5.2, entradas ordenadas append-only | No | Snapshot inicial inmutable, log 1, población compartida; reconstrucción completa antes de firmar | Perfil limitado; sin servicio público ni evolución operacional |
| TBSCertificateLogEntry | §5.2.1 | No | DER conservando campos del TBS, sustitución SPKI por algoritmo y hash; omitir serial y signature | Formato exacto del perfil soportado |
| Merkle tree | §4, RFC9162 | No | Árbol independiente, partición por mayor potencia de dos; no duplicar hojas impares | Exacto |
| Inclusion proof | §4.3, §6.2 | No | Verificador separado con índices absolutos y subárbol alineado | Exacto |
| Checkpoint | §5.2, §5.3 | No | Snapshot firmado, timestamp no nulo, hash de todas las entradas | Exacto para snapshot inicial |
| Subtree signatures | §5.3.1, §6.3 | EVP firma/verifica | Mensaje separado por dominio, timestamp cero para certificados | Exacto |
| Cosignatures | §7.3, política configurable | EVP | CA y un cosigner adicional local; ambos reconstruyen el snapshot; claves distintas | Criptografía exacta; no independencia operacional ni transparencia pública |
| Standalone certificate | §6.2–6.3 | X509 contenedor sí, firma MTC no | MTCProof en signatureValue; dos subárboles de cobertura según §4.5 | Formato exacto; perfil experimental |
| Landmark-relative certificate | §6.4 | No | Secuencia inicial [0,N], selección de subárbol, signatures vacío | Formato exacto; un landmark activo |
| Landmark distribution | §7.4 | No | Configuración local autenticada con checkpoint y cobertura de sus subárboles; medir bytes y validación previa | Transporte OOB local; sin servicio de actualización ni caché persistente |
| CA identification | §5.1 | OID/Name genéricos | Identificadores privados de documentación 32473.*, OID experimental que prescribe -05 | Exacto para experimentación |
| Trust anchor identification | §5.1, §8 | No | IDs binarios RELATIVE-OID y landmark específico | Perfil limitado |
| TLS negotiation/signalling | §8 y TAI -04 §4 | Custom extensions | Listas en CH/EE y confirmación vacía en CertificateEntry 0; código privado 0xffa7, coincidencia exacta, rechazo si falta | Experimental: no código IANA, grupos/retry/múltiples rutas no implementados |
| Certificate message | §8 | Sí | Certificado X509 MTC íntegro, sin RPK ni encapsulación compacta | Exacto |
| CertificateVerify | TLS 1.3 | Sí | Mantener firma nativa con la clave original del servidor | Exacto |
| Finished | TLS 1.3 | Sí | Mantener procesamiento nativo | Exacto |
| Hostname validation | X509/TLS | Sí | X509_check_host y validación nativa de hoja tras autenticación MTC | Perfil de hoja DNS servidor |
| Validity validation | X509 | Sí | Fechas de hoja comprobadas durante TLS; trust snapshot autenticado previamente | Exacto para hoja |
| Path validation | §7.2 reemplaza solo autenticación de firma | Parcial | Validar MTC y aplicar controles X509 de hoja; trust config directa §7.1, sin CA intermedia | Limitación explícita; no validador PKIX MTC general |
| Revoked ranges | §7.5 | No para config MTC | Limitar seriales al log y rango emitido; rechazar fuera de rango | Snapshot estático; sin actualización de revocaciones |
| CA certificate representation | §5.5 opcional como fuente de configuración | No | Configuración directa §7.1 con claves SPKI; no simular un certificado CA auto-firmado | Alternativa permitida; formato OOB de laboratorio |

## Decisiones y límites de la comparación

La implementación se denominará **MTC-experimental**, incluso si los formatos
centrales siguen -05. Los escenarios llevarán `mtc-experimental` en el nombre.
No habrá afirmación de conformidad integral IETF, interoperabilidad ni despliegue
Web PKI. Las limitaciones de negociación, ciclo de vida del log y validación de
rutas no se ocultarán bajo flags de línea de comandos.

Las claves de CA MTC deben ser distintas de las CA X509 (§5.4). Se conservarán
claves de servidor, nombres, fechas y población. Las extensiones de identificación
de emisor que referencien la CA anterior requieren adaptación u omisión documentada.
ECDSA P-256 y ML-DSA-65 son familias de continuidad experimental, no niveles de
seguridad nominal idénticos. El intercambio se mantiene en X25519.

La política por defecto añade un cosigner local a la CA. X509 anterior no incluye
SCTs: standalone con cosignatura y X509 sin CT no tienen propiedades equivalentes.
Se desglosarán firmas y prueba. El modo landmark desplaza autenticación a la
configuración previa, cuyo coste se contabilizará; no se presumirá amortización.

La instrumentación se reutiliza en una copia independiente de la versión perfilada,
con prefijo `/opt/openssl-mtc`. Se validarán primero fixtures/verificadores,
después TLS negativo y regresiones, después smoke y campaña completa. Los tamaños
de escalado se obtendrán de las codificaciones reales, no de una fórmula asumida.
