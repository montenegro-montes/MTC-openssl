# Protocolo compacto de laboratorio v2

## Separación de versiones

`docker/Dockerfile.compact` parte de `mt-tls-lab:local` y construye un tercer ejecutable,
`/opt/openssl-compact/bin/openssl`. Copia los fuentes a
`/opt/src/openssl-compact`, aplica `compact/patch.py` y conserva los ejecutables
original y Merkle adicional en sus ubicaciones previas. No modifica libssl.

El soporte RPK de OpenSSL permite enviar SubjectPublicKeyInfo en Certificate.
Una extensión privada nueva, `0xffa6`, transporta la credencial y prueba Merkle
en EncryptedExtensions. Todo queda vinculado al transcript de TLS y al
CertificateVerify habitual. La extensión `0xffa5` de la fase anterior permanece
independiente. No se mezclan los dos modos en una misma conexión.

Fuentes primarias: [RPK en OpenSSL](https://docs.openssl.org/3.4/man3/SSL_get0_peer_rpk/),
[negociación del tipo de certificado](https://docs.openssl.org/3.2/man3/SSL_set1_server_cert_type/),
[RFC 7250](https://datatracker.ietf.org/doc/html/rfc7250). La credencial y los
formatos de raíz de este experimento son propios, no están definidos por RFC 7250.

## Credencial y confianza

La credencial contiene un único nombre DNS, fechas de validez, SHA-256 del DER
SubjectPublicKeyInfo y propósito `serverAuth`. La clave se envía una sola vez,
en Certificate/RPK. No se envía la firma individual de la credencial: la autoridad
firma una raíz Merkle que autentica el conjunto.

El generador valida los certificados fuente contra la CA y el hostname con
propósito sslserver antes de emitir las credenciales. Las identidades adicionales
del lote tienen certificados y claves independientes. El periodo de la raíz es
la intersección de las validades de la CA y de todos los certificados del lote.

El cliente configura la CA de confianza fuera de banda, igual que en el escenario
X.509. Valida la firma de la raíz con su clave pública, su identificador, el
periodo de la CA/raíz y la pertenencia de la credencial al árbol. Comprueba nombre,
propósito, periodo de la credencial y hash de la clave RPK realmente recibida.
Solo entonces acepta la autenticación de la clave; OpenSSL comprueba después
CertificateVerify y Finished. Un retorno de éxito de este callback **no significa
validación X.509 de un certificado hoja**: significa validación de la credencial
compacta mediante la autoridad y el árbol.

En modo warm el cliente verifica la firma del archivo de raíz durante la
configuración, antes del handshake medido. En modo cold la raíz firmada llega
en la extensión y se verifica dentro del handshake. El servidor no es una
fuente de confianza: una raíz enviada por él requiere una firma válida de la
CA configurada. En ambos casos se comprueba la vigencia en la conexión.

La negociación exige exclusivamente RPK en modo compacto y nunca acepta un
fallback X.509 silencioso. Faltas de extensión, raíces desconocidas, errores de
formato o de autenticación abortan. No se permiten PSK, reanudación, early data,
QUIC, DANE ni versiones anteriores a TLS 1.3 en este modo. Se exige
`-verify_hostname`; solo se admite un nombre DNS, sin wildcard. Las comprobaciones
de fechas usan el reloj real del sistema. No se implementa autenticación compacta
del cliente ni un protocolo de revocación; una raíz solo se deja de aceptar al
retirarla de la configuración o expirar. El modo cold acepta cualquier lote
vigente correctamente firmado por la autoridad, no mantiene una lista de lotes
revocados ni evita volver a presentar otro lote que siga vigente.

La política de laboratorio admite claves EC de 256 bits y ML-DSA-65. No reproduce
todos los perfiles, restricciones, políticas y mecanismos de revocación de una
PKI X.509 general. El experimento compara identidades, claves y confianza
controladas, con una CA directa y sin revocación online en ninguna variante.

## Formatos

Todos los enteros están en orden de red. No se serializan estructuras de C.

Credencial `MTC2` (55 + longitud DNS bytes):

| Campo | Bytes |
|---|---:|
| `MTC2` | 4 |
| Longitud DNS | 2 |
| DNS ASCII en minúsculas, sin terminador | 1–253 |
| notBefore, segundos Unix | 8 |
| notAfter, segundos Unix | 8 |
| SHA-256 de SPKI DER | 32 |
| Propósito: 1 = serverAuth | 1 |

Se aplica `H(00 || credencial)` para cada hoja y `H(01 || izquierda || derecha)`
para los padres. Se conserva la duplicación de nodos impares del prototipo.
La prueba usa el formato `MTP1` de la fase anterior, sobre estas nuevas hojas.
Número de hojas, índice, profundidad y hermanos duplicados se validan contra
la raíz firmada; no basta con encontrar un hash coincidente.

Raíz firmada `MTR2`:

| Campo | Bytes |
|---|---:|
| `MTR2` | 4 |
| Número de hojas | 4 |
| Raíz SHA-256 | 32 |
| notBefore / notAfter | 8 + 8 |
| SHA-256 de SPKI de la autoridad | 32 |
| Longitud de firma | 2 |
| Firma sobre los primeros 88 bytes | Variable |

La clave de autoridad configurada determina el algoritmo: ECDSA/SHA-256 o
ML-DSA-65. El identificador de la autoridad debe coincidir antes de verificar.

Bundle `MCB2`: magic de 4 bytes, longitud de credencial (2), credencial,
longitud de prueba (2), prueba, longitud de raíz firmada (2) y raíz firmada.
El bundle persistido tiene longitud de raíz cero. El servidor añade la raíz
solo para cold. El límite total es 8192 bytes; se exigen longitudes exactas.

ClientHello warm: versión `02`, modo `00`, hash de raíz (32 bytes).
ClientHello cold: versión `02`, modo `01`. Un servidor sin la raíz pedida por
warm aborta; no cambia automáticamente a cold.

## Opciones nativas nuevas

- Cliente warm: `-compact_authority ca.pem -compact_root root.signed -verify_hostname server`.
- Cliente cold: `-compact_authority ca.pem -compact_cold -verify_hostname server`.
- Servidor: `-compact_bundle bundle-0000.bin -compact_signed_root root.signed`,
  además de su certificado/clave locales para seleccionar la clave TLS; solo
  la parte pública RPK se transmite.
- Cliente: `-lab_metrics` emite una línea JSON al completar el handshake.
  No se combina con `-msg` o `-trace`.
