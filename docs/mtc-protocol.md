# Protocolo implementado: MTC-experimental

Referencia fija: [draft-ietf-plants-merkle-tree-certs-05](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-05.txt),
con [trust-anchor-ids -04](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-04.txt).
The validation boundary is documented in [validation](validation.md). It is not an implementation
integral de IETF MTC ni una variante del formato compacto anterior.

## Credencial y autenticación

Se genera un certificado DER X509 v3. El issuer utiliza el OID experimental
1.3.6.1.4.1.44363.47.1 del borrador y un CA ID en UTF8String. El serial combina
log 1 e índice. Ambas posiciones de AlgorithmIdentifier usan
1.3.6.1.4.1.44363.47.0 sin parámetros. signatureValue contiene MTCProof sin
encapsulado ASN.1 adicional, aparte del BIT STRING del propio Certificate.

TBSCertificateLogEntry conserva versión, emisor, vigencia, sujeto y extensiones;
contiene algoritmo de clave y SHA256 del SPKI DER en lugar del SPKI completo.
No contiene serial ni algoritmo de firma. La entrada del log incorpora la lista
de extensiones vacía y tipo 1, seguidos del contenido DER de esa secuencia.
El antiguo authorityKeyIdentifier se omite porque identifica una CA distinta.
Las claves de servidor, SAN, propósito y vigencia se conservan.

El árbol usa SHA256 y estructura RFC9162, sin duplicar hojas impares. Cada snapshot
inicial pasa de 0 a N. Los subárboles de cobertura se seleccionan con §4.5.
Por ejemplo, N=16 se cubre con [0,8) y [8,16): las pruebas tienen tres hashes,
no cuatro. N=1 tiene prueba vacía pero contiene todos los demás campos obligatorios.

La CA y un cosigner adicional mantienen copias locales completas del snapshot.
Cada uno reconstruye el hash antes de firmarlo. Los mensajes de firma usan
CosignedMessage y separación de dominio de -05. Los certificados standalone
incluyen dos firmas de subárbol con timestamp cero. El checkpoint OOB usa
un timestamp no nulo. La política exige ambas firmas.

La secuencia de landmarks inicial es [0,N]. El certificado landmark contiene
la misma información X509 y la prueba al subárbol elegido, con lista de firmas
vacía. El cliente verifica previamente las firmas del checkpoint y comprueba
que los subárboles cubren exactamente el snapshot y reconstruyen su raíz.
Este caso inicial tiene una comprobación de consistencia directa; no implementa
el algoritmo general de consistencia entre snapshots sucesivos ni pruning.

## Confianza y sus archivos

`authority.bin` almacena CA ID, dos cosigner IDs/SPKI, log y límites de serial.
Standalone carga exclusivamente ese archivo: no requiere un checkpoint previo.
`trust.bin` añade landmark, checkpoint firmado y subárboles. Landmark autentica
este material antes de iniciar el handshake. El formato MCF1 de estos archivos
es almacenamiento OOB del laboratorio, **no un formato de certificado IETF**.
La distribución inicial de claves y política se considera configuración confiable
del operador. No se demuestra seguridad de un servicio de distribución remoto.

Las claves de CA/cosigner MTC son distintas de la CA X509, cumpliendo la restricción
de separación de claves. Se limita la aceptación al rango emitido del log 1.
No hay actualización dinámica de revocaciones ni persistencia de estado entre
procesos cliente. Los archivos y su coste de validación no se consideran gratuitos.

## TLS

Todos los escenarios usan TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, autenticación
solo de servidor y ausencia de tickets/reanudación. El certificado MTC viaja en
Certificate X509 normal, y OpenSSL conserva CertificateVerify y Finished.
MTC autentica la credencial; CertificateVerify prueba posesión de la clave TLS.
Sus bytes se miden por separado.

Se implementan las listas solicitada/disponible en ClientHello/EncryptedExtensions
y la confirmación vacía en CertificateEntry 0 de TAI -04, usando **0xffa7 privado**.
La selección admite coincidencia exacta con un CA ID o landmark específico.
No se implementan grupos, negociación de cosigners, reintentos ni rutas alternativas.
La configuración de cada servidor fija un certificado; el cliente debe anunciar
el identificador correspondiente. No es un reemplazo silencioso por un flag:
la señal viaja en TLS y se exige su confirmación antes de validar la credencial.

El callback valida MTC y luego aplica controles nativos X509 de hoja, tratando
esa hoja ya autenticada como ancla local para esa comprobación. Se comprueban
hostname, fechas, propósito y extensiones críticas. **No constituye un validador
PKIX MTC general:** no construye cadenas MTC arbitrarias ni hereda restricciones
de certificados CA intermedios. Se fuerza SSL_VERIFY_PEER al activar MTC.

## Límites normativos

Los nombres de escenario incluyen `mtc-experimental`. El snapshot local, el cosigner
sin independencia operacional, la validación limitada de rutas y la extensión
privada impiden presentar los resultados como interoperabilidad o conformidad
completa. No se implementan servicio público de log/monitorización, ACME, pruning,
consistencia general de actualizaciones, OCSP/CRL ni ecosistema de transparencia.
Se rechazan extensiones de entrada no vacías en este perfil en lugar de fingir
soporte de extensiones futuras. La semántica X509 de hoja es más rica que la
credencial compacta mínima, pero no equivale a implementar todas las funciones PKI.
