# Protocolo implementado: MTC-experimental

Referencia fija: [draft-ietf-plants-merkle-tree-certs-07](https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-07.txt),
con [trust-anchor-ids -06](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-06.txt).
The validation boundary is documented in [validation](validation.md). It is not an implementation
integral de IETF MTC ni una variante del formato compacto anterior.

## Credencial y autenticación

Se genera un certificado DER X509 v3. El issuer utiliza el OID asignado
1.3.6.1.5.5.7.25.3 (id-rdna-trustAnchorID) y un CA ID codificado como
RELATIVE-OID. El serial combina log 1 e índice. Ambas posiciones de
AlgorithmIdentifier usan 1.3.6.1.5.5.7.6.67 (id-alg-mtcProof) sin parámetros.
signatureValue contiene MTCProof sin
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
CosignedMessage y separación de dominio de Draft-07. Los certificados standalone
incluyen dos firmas de subárbol con timestamp cero. El checkpoint OOB usa
un timestamp no nulo. La política exige ambas firmas.

La secuencia de landmarks inicial es [0,N]. El certificado landmark contiene
la misma información X509 y la prueba al subárbol elegido, con lista de firmas
vacía. El cliente verifica previamente las firmas del checkpoint y comprueba
que los subárboles cubren exactamente el snapshot y reconstruyen su raíz.
Este caso inicial tiene una comprobación de consistencia directa; no implementa
el algoritmo general de consistencia entre snapshots sucesivos ni pruning.

## Confianza y sus archivos

`authority.bin` usa MCA2 y almacena CA ID, cosigner IDs/SPKI, log y límites de serial.
Standalone carga exclusivamente ese archivo: no requiere un checkpoint previo.
`trust.bin` usa MTB2 para combinar la autoridad MCA2, un checkpoint MCP2 y la
identidad de landmark explícita. Landmark autentica este material antes de iniciar
el handshake. Estos formatos son almacenamiento OOB del laboratorio, **no formatos
de certificado IETF**.
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
y la confirmación vacía en CertificateEntry 0 del subconjunto TAI -06, usando
**0xca34 provisional**, alineado con Chromium/BoringSSL (no asignación IANA
definitiva). El laboratorio utilizó históricamente `0xffa7` privado; esas
evidencias se conservan. Una configuración de `s_server` puede cargar las
credenciales Standalone y Landmark de la misma identidad, comparar sus IDs
individuales y el grupo inicial Landmark, y anunciar los IDs individuales
elegibles en orden de preferencia. Si no coincide ninguno y Standalone es
elegible, envía esa credencial de respaldo sin el marcador vacío. La señal viaja
en TLS y el cliente exige su confirmación antes de validar la credencial
seleccionada.

Un grupo Landmark `caID.2.N.L` también contiene el ID Standalone `caID`
(MTC -07 §8.2.1). Si Landmark no es elegible para TLS y se envía Standalone,
esa selección coincide con el grupo solicitado y lleva el marcador vacío.

El cliente de validación ordinario sigue configurado con una confianza MTC
por conexión. El runner de reintento aislado acepta una lista disponible de
varios IDs, pero solicita un ID por conexión y solo puede autenticar el ID de
su confianza local. El preflight ha validado conexión directa y un reintento
acotado con credencial Landmark; no constituye negociación general de grupos,
cosigners o múltiples almacenes de confianza.

El servidor pareado admite exactamente dos credenciales de la misma identidad
MTC. Tras ClientHello, su callback de certificado comprueba cada candidato con
`SSL_check_chain` y conserva los que tienen `CERT_PKEY_VALID`. Selecciona entre
ellos y construye la lista de EncryptedExtensions para esa conexión, con los IDs
individuales elegibles en orden Landmark, Standalone. Si no queda ningún
candidato elegible, interrumpe el handshake antes de EncryptedExtensions. El
cliente del runner pareado anuncia `X25519:P-256` en `supported_groups` para que
OpenSSL admita las hojas ECDSA-P256; la clave efímera negociada sigue siendo
X25519. Las capturas de la pareja ECDSA-P256 y el fallback comprueban ambos IDs
elegibles, la selección y el marcador. El caso de un solo candidato elegible
está cubierto por una prueba TLS en memoria que comprueba la lista de
EncryptedExtensions y la ausencia de marcador en fallback. Esa prueba usa
registro interno de certificados P-256/P-384 de identidades MTC distintas:
demuestra el filtrado TLS por conexión, pero no la vinculación MTC de una pareja
mixta ni una captura de red de ese caso. Esa limitación acota la evidencia de
TAI -06 §5.6.

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

## IDs de negociación inicial y de selección

Para CA `32473.101`, standalone conserva `32473.101`. El grupo inicial es
`32473.101.2.1.1`; el landmark seleccionado y el retry explícito conservan
`32473.101.1.1.1`. Los constructores usan caid y log de MCA2 y el número de
landmark explícito de MTB2,
sin sustituir globalmente `.1` por `.2`. El servidor reconoce el grupo del
landmark configurado; el cliente verifica el individual seleccionado.
La restricción de carga a log 1 / landmark 1 sigue vigente. El codepoint sigue
siendo `0xca34` provisional. Las capturas de servidor pareado Standalone y
Landmark, sus informes conjuntos y el preflight del reintento han pasado para
esta configuración ECDSA-P256. No se afirma conformidad completa con el draft.

## Evidencia local de la imagen v2

Las comprobaciones del 30–31 de octubre de 2026 usaron el ID inmutable de
imagen Docker local
`sha256:73c86d1dc472dde4bef9a414cdbd478795b2623b21355b57b1bd9be7fc224cb6`.
El `MTC_SHA256` incluido en ella es
`7cd8e2233b9f9365352931e67b42e2973486753ef7efcd80092838cdd9ce6dfa`.
Estos valores identifican la imagen local y el parche MTC construido; no son
un digest de publicación en un registro de contenedores.

| Caso | Evidencia local | Alcance comprobado |
| --- | --- | --- |
| Pareja, Standalone | `artifacts/protocol-review/tai06-final-v2-standalone-20261030T220555Z/standalone-joined.json` | `overall: PASS` para objeto y transcripción TLS; selección Standalone y marcador. |
| Pareja, Landmark | `artifacts/protocol-review/tai06-final-v2-landmark-20261031T083849Z/landmark-joined.json` | `overall: PASS` para objeto y transcripción TLS; selección Landmark y marcador. |
| ID ajeno | `artifacts/protocol-review/tai06-final-v2-fallback-20261031T084123Z/transcript.log` | El inspector del transcript pasó: ambos IDs en EncryptedExtensions, fallback Standalone y ausencia de marcador. El cliente terminó con código 1. |
| Un certificado, Standalone | `artifacts/protocol-review/tai06-final-v2-legacy-standalone-20261031T084443Z/standalone-joined.json` | `overall: PASS` para objeto y transcripción TLS. |
| Un certificado, Landmark con estado RP | `artifacts/protocol-review/tai06-final-v2-legacy-landmark-rp-20261031T101646Z/landmark-joined.json` | `overall: PASS` para objeto y transcripción TLS; ClientHello solicitó `32473.101.2.1.1`. |

Una primera captura heredada Standalone con el fixture `browser` terminó en
`FAIL` porque ese certificado identifica `server.mtc.example.com` y el runner
heredado comprueba `server`. Se conserva en
`artifacts/protocol-validation/tai06-final-v2-legacy-standalone-20261031T084205Z/`;
no se cuenta como prueba de compatibilidad. La repetición empleó el fixture
heredado compatible con `server`.

La primera captura heredada Landmark completó el handshake, pero su extracción
offline terminó en `FAIL`: sin estado RP retenido, el cliente solicitó el CA ID
`32473.101` y recibió la credencial Landmark. Se conserva en
`artifacts/protocol-validation/tai06-final-v2-legacy-landmark-20261031T084922Z/`.
El runner ofrece `--landmark-rp-state` de forma explícita para cargar el estado
RP autenticado y solicitar el grupo `32473.101.2.1.1`; la captura nueva y su
informe conjunto pasaron. El modo heredado por defecto no se ha cambiado.

## IDs con componentes grandes: imagen local posterior

La imagen local `sha256:faaa86f994ed86292f73ecd52abd6920b60e672e6f72a5d6a64ce573226a3a33`
incorpora `MTC_SHA256=6c009cef1ca378180a324ca08ad45865ce4e76a2f5a716af6483f5a8eacbfd04`;
el operador comprobó que ese hash coincide con los cinco archivos MTC usados
en la compilación. No es un digest de publicación en un registro.

TAI -06 §8 exige (MUST) aceptar en TLS los IDs válidos cuyos componentes OID
sean arbitrariamente grandes y permite (MAY) descartar los no admitidos por la
configuración local. Los parsers de ClientHello y EncryptedExtensions validan
la codificación canónica en bytes sin convertir cada componente a `uint64_t`;
después omiten los IDs que exceden el límite local `UINT64_MAX`. Este límite
local de configuración sigue vigente. Un ID válido con un componente 2^64 y
longitud total de 10 bytes fue probado como único ID y antes de un grupo MTC
conocido. Los tests C offline pasaron dentro de la imagen nueva. En tres
handshakes TLS en memoria comunicados por el operador, el caso `group` mantuvo
la selección Standalone con marcador; `large-only` produjo fallback Standalone
sin marcador; y `large-group` seleccionó Standalone con marcador. En los tres
casos EncryptedExtensions anunció solo el ID individual Standalone elegible.
Un cuarto handshake en memoria con ambas credenciales ECDSA-P256 elegibles,
`both-large-group`, seleccionó Landmark, anunció primero su ID individual y
después el de Standalone, y emitió el marcador. Este cuarto caso comprueba la
lista completa de dos IDs para la imagen posterior, sin constituir una captura
de red ni una validación de credenciales MTC por el cliente de la prueba.

Los tres primeros casos en memoria usan registro interno de credenciales de
curvas distintas para forzar la elegibilidad TLS; el cuarto usa dos
credenciales ECDSA-P256. No prueban una captura de red ni la validación MTC de
una pareja mixta. Las capturas e informes de la sección anterior corresponden
a la imagen v2, no a esta imagen posterior.

Tras corregir el controlador Python, el operador comunicó `Ran 22 tests ... OK`
para `test_retry.py` ejecutado con el repositorio montado en modo lectura. El
test C nativo `test_retry_native.c` volvió a pasar dentro de la imagen posterior;
incluye ahora `CertificateRequest` con un ID de componente 2^64 solo y seguido
por un ID conocido, además de una codificación no canónica. Es prueba offline
del parser y del marcador de presentación del cliente.

Un test TLS 1.3 en memoria adicional completó ambas mitades del handshake con
`CertificateRequest` que contenía el ID grande seguido del conocido: el cliente
presentó un certificado y el servidor recibió el marcador vacío. En ese test se
reutilizó una hoja de servidor como certificado de cliente y el servidor aceptó
la verificación mediante un callback permisivo, exclusivamente para comprobar
el recorrido de la extensión. No demuestra autenticación MTC mutua ni una
captura de red. Un primer intento falló al cargar la hoja antes de instalar el
callback MTC del cliente; al corregir el orden de inicialización, el handshake
en memoria pasó. El código de producción no cambió por ese ajuste del test.

El `MTC_SHA256` de la imagen no incluye `retry.py` ni los archivos de prueba
montados desde el repositorio: su procedencia final requiere fijar también una
revisión del código fuente.
