# Método de comparación para el paper

## Factores controlados

Ocho variantes, mismas bibliotecas y mismo ejecutable instrumentado. TLS 1.3,
X25519 y TLS_AES_256_GCM_SHA384 fijos; sin tickets ni reanudación; autenticación
solo del servidor. Cada comparación dentro de una familia mantiene el mismo
certificado/clave de servidor y clave de autoridad. El generador construye
árboles X.509 y compactos con la misma población y número de hojas.

ECDSA P-256 y ML-DSA-65 no representan el mismo nivel nominal de seguridad
(P-256 ofrece aproximadamente 128 bits clásicos; ML-DSA-65 es categoría 3).
Se conservan las elecciones de la fase inicial. No atribuir a Merkle diferencias
entre esas familias: contrastar cada variante con su propia línea base.
X25519 sigue siendo clásico: este estudio aísla autenticación poscuántica,
no afirma que todo el intercambio TLS sea poscuántico.

La fase anterior conserva sus árboles de dos hojas y sus mediciones originales.
En el banco compacto nuevo, las variantes de Merkle adicional usan árboles del
mismo tamaño que el compacto. Las ejecuciones preliminares anteriores al
emparejamiento de poblaciones no se deben mezclar con la serie controlada.

## Qué se mide

`handshake_wall_ms`: reloj monotónico entre SSL_CB_HANDSHAKE_START y
SSL_CB_HANDSHAKE_DONE del cliente. Incluye esperas de red y procesamiento TLS de
ambos extremos, excluye creación del proceso, carga inicial de archivos,
conexión TCP y petición HTTP. No es una medición de una única primitiva.

`handshake_client_cpu_ms`: CPU del proceso cliente durante ese intervalo.
No mide CPU del servidor. No inferir consumo total del sistema a partir de ella.

`transport_read_bytes` y `transport_written_bytes`: contadores BIO durante el
handshake. Incluyen los registros TLS, pero no cabeceras IP/TCP/Ethernet,
retransmisiones ni el establecimiento TCP. Se suman para comparar el total TLS.
Los contadores de mensajes separan Certificate, CertificateVerify y
EncryptedExtensions, incluyendo sus cabeceras de handshake. Certificate/RPK
no es un archivo X.509, aunque conserve el nombre del mensaje TLS.

`compact_setup_ms`: preparación de la configuración compacta. Incluye carga de
la autoridad y, en warm, carga y validación de la raíz firmada antes del handshake.
No es exclusivamente tiempo de verificar una firma.

`client_process_http_wall_ms`: tiempo del proceso completo, incluidos arranque,
configuración, TCP, TLS, HTTP de diagnóstico y cierre. No sustituye a la medida
de handshake, y el HTTP de diagnóstico puede variar entre configuraciones.

Cada muestra usa un proceso nuevo. Por tanto, la raíz warm se vuelve a validar
al configurar cada proceso; no hay una caché autenticada persistente entre
procesos. La medición del handshake representa una raíz ya validada al empezar
TLS; el coste de hacerlo **no desaparece**: se registra por separado y queda
incluido en el tiempo de proceso completo. Una aplicación persistente podría
amortizar ese coste, pero eso no se mide directamente en este ejecutor.

Los tiempos offline del manifiesto incluyen procesos Python/OpenSSL, generación
de fixtures, extracción de credenciales, construcción de árbol/pruebas y firma
de raíz. No compararlos numéricamente con el tiempo C aislado del verificador.
La emisión de certificados adicionales es preparación del dataset, no un coste
necesario del protocolo compacto en un despliegue real.

## Muestreo y análisis

Tres calentamientos por variante, excluidos del CSV de muestras y conservados en
logs. Treinta rondas por defecto, una conexión por escenario y orden aleatorio
con semilla fija dentro de cada ronda. Se usan procesos servidor persistentes
separados y cliente en otro contenedor por red bridge de Docker.

Se guardan todas las muestras válidas, medianas/rangos e intervalos bootstrap
(percentiles 2,5/97,5; 2000 remuestreos) para la mediana de diferencias
emparejadas por ronda frente a X.509 de la misma familia. Es un análisis
exploratorio de una ejecución, sin ajuste por comparaciones múltiples ni
replicaciones independientes. Si un intervalo temporal incluye cero, esa serie
no distingue de forma clara una mejora de un empeoramiento.

No seleccionar solo la variante favorable ni comparar el tiempo warm con cold
sin mostrar qué trabajo se ha desplazado antes del handshake. Publicar también
el tiempo de proceso completo y el coste de precargar/renovar la raíz.

## Interpretación del tamaño

Merkle adicional conserva el certificado y añade una prueba: se espera aumento.
El compacto elimina la firma X.509 individual y otros campos, pero conserva la
clave pública y la firma TLS CertificateVerify. Su prueba crece como
32 × ceil(log2(N)) bytes, además de campos fijos.

Warm excluye la raíz firmada del tráfico de cada conexión. Cold la incluye:
puede anular el ahorro de haber eliminado una firma individual. El resultado
no es "Merkle siempre reduce TLS"; depende de N, algoritmo, distribución de
raíces y número de conexiones que amortizan cada lote.

Si una raíz firmada ocupa R bytes y se distribuye una vez para H conexiones,
el coste bruto de ese objeto amortizado es R/H bytes por conexión, **más** el
protocolo de distribución, CA de confianza si procede, renovaciones y fallos de
caché. No se ha implementado ni medido un servicio de distribución externo.

## Para ampliar el estudio

Repetir en máquinas/arquitecturas y ejecuciones independientes; fijar recursos
Docker y registrar CPU física/carga; explorar N y algoritmos dentro de políticas
compatibles; medir escenarios de red con latencia/ancho de banda definidos y
CPU del servidor. Para publicación, congelar imagen por digest y fuentes por
commit, conservar las entradas públicas necesarias y excluir claves privadas.
El entorno actual no es reproducible bit a bit por usar base/paquetes no fijados
por digest/versiones; los hashes y metadatos identifican la ejecución observada.

La política compacta de este laboratorio es más limitada que una PKI general.
La equivalencia experimental se limita al perfil de CA directa, DNS único,
serverAuth y vigencia usado aquí, sin revocación online en ninguna variante.
