# Comparación conceptual y alcance científico

MTC se basa en `draft-ietf-plants-merkle-tree-certs-05`. En este repositorio se mide
un perfil **MTC-experimental**, con las desviaciones documentadas en
[mtc-protocol.md](mtc-protocol.md). Las mediciones no representan una validación
de conformidad ni un despliegue completo del borrador IETF.

| Esquema | Semántica X509 implementada | SPKI | Prueba Merkle | Firma CA en TLS, aparte de CertificateVerify | Confianza compartida | Estado |
|---|---|---|---|---|---|---|
| X509 tradicional | Validación nativa del escenario, sin CT | Dentro de X509 | No | Firma individual de hoja | CA X509 | Mecanismo estándar |
| RPK fijado | Asociación local identidad-clave | RPK | No | No | Clave fijada OOB | RFC RPK; control local experimental |
| Compacto warm | DNS, vigencia, serverAuth mínimos | RPK, hash en credencial custom | Sí, formato previo | No | CA y raíz firmada precargada | Experimental propio |
| Compacto cold | Igual que warm | Igual que warm | Sí | Firma de raíz compartida | CA precargada; raíz transmitida | Experimental propio |
| MTC-experimental standalone | Campos X509 de hoja, validación de rutas limitada | Dentro de X509 | Inclusión de entrada TBSCertificateLogEntry | Firma de subárbol CA y un cosigner local | Claves/política CA y cosigner | Perfil del Internet-Draft -05, sin conformidad integral |
| MTC-experimental landmark | Igual que standalone | Dentro de X509 | Inclusión al subárbol landmark | Ninguna en MTCProof | Claves/política y landmark autenticado OOB | Mismo perfil experimental |

CertificateVerify y Finished permanecen en todos los escenarios. Ninguna fila
elimina la prueba de posesión de la clave privada TLS.

## Cómo separar los efectos

1. X509 frente a RPK cuantifica el efecto conjunto de contenedor y modelo de
   autenticación; no es una comparación con propiedades de PKI equivalentes.
2. RPK frente a compacto añade credencial mínima y prueba. Los tamaños publicados
   por la fase de perfilado siguen disponibles; no se mezclan sus tiempos con la
   campaña MTC como si fueran muestras emparejadas.
3. X509 frente a MTC conserva el contenedor X509, cambia la autenticación CA y
   agrega una prueba. En standalone también se exige una cosignatura adicional;
   X509 base no lleva SCTs. El mayor tamaño de standalone no es evidencia de que
   el diseño IETF sea ineficaz en una PKI con transparencia equivalente.
4. Standalone frente a landmark desplaza firmas a material compartido fuera de
   TLS. Deben contabilizarse distribución y validación previas, así como demora
   de emisión, actualización y almacenamiento no representados por el handshake.
5. Compacto frente a MTC compara arquitecturas. MTC mantiene atributos y
   extensiones X509 más ricos; compacto omite, entre otras funciones, validación
   general de cadenas, políticas, name constraints y mecanismos PKI extensibles.
   Este perfil MTC tampoco implementa toda esa maquinaria de rutas: no se le
   atribuyen las capacidades de una implementación IETF/PKIX completa.

Las diferencias de CPU incluyen parser, proveedor criptográfico y forma de
integración en OpenSSL. Las medidas por sí solas no aíslan el coste abstracto
de un árbol Merkle. Las diferencias de tamaño distinguen DER, prueba, firmas,
mensajes y registros. El estudio no considera P-256 y ML-DSA-65 niveles de
seguridad nominal idénticos.

## Amortización

Puede calcularse un umbral teórico `ceil(D / (B_standalone - B_landmark))`, donde
D es el material distribuido una vez y B son bytes por handshake. Se reportan
D completo y D incremental respecto a claves/política comunes. Para una política
real también cuentan renovación, refresco, fallos y distribución de múltiples
landmarks. Aquí cada muestra crea un proceso y vuelve a cargar/verificar el archivo:
**no se observa una caché reutilizada ni amortización temporal real**.

Los [resultados](mtc-results.md) responden con datos del perfil medido, distinguiendo
la campaña principal del escalado exploratorio y las limitaciones pendientes.
