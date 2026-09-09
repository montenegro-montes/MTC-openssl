# Verificación local — 2026-09-09

Docker Desktop, contenedores Linux arm64. Imagen construida correctamente con
OpenSSL 3.5.8, liboqs 0.14.0 y oqsprovider 0.10.0. Se conserva el ejecutable
original y se construye otro con las opciones Merkle de cliente y servidor.

- Compose válido; sintaxis Bash y compilación Python correctas.
- 153 rutas de prueba Merkle válidas (árboles de 1 a 17 hojas), junto a mutaciones,
  truncaciones y entradas inválidas, pasan con AddressSanitizer y UBSan.
- 50 comprobaciones TLS pasan sobre ECDSA P-256 y ML-DSA-65: conexión válida,
  HelloRetryRequest, interoperabilidad normal y rechazo de raíz/prueba/hoja
  incorrectas, CA/hostname incorrectos, expiración y prueba ausente.
- Un peer exclusivo de pruebas envía por red versiones, índices, profundidades
  y longitudes de prueba inválidos; el cliente rechaza todos los casos.
- Se comprueba el rechazo de PSK, sesiones de entrada, reconnect, early data,
  raw public keys, modo avanzado y DANE, así como la exigencia de identidad.
- Los dos escenarios Merkle completan conexiones HTTP verificadas entre los
  servicios cliente y servidor de Compose, con dos muestras funcionales cada uno.
- `C/` y `Bash/` permanecen sin modificaciones respecto del contenido recibido.
  Las advertencias de funciones sin uso en los fuentes originales permanecen.

Tamaños observados en las comprobaciones funcionales, usando los mismos
certificados, X25519 y TLS_AES_256_GCM_SHA384:

| Escenario | Hoja DER (bytes) | Handshake leído por cliente (bytes) | Escrito (bytes) |
|---|---:|---:|---:|
| ECDSA P-256 | 444 | 815–816 | 400 |
| ECDSA P-256 + Merkle | 444 | 897 | 405 |
| ML-DSA-65 | 5563 | 9172 | 400 |
| ML-DSA-65 + Merkle | 5563 | 9253 | 405 |

El árbol de demostración tiene dos hojas: payload de prueba de 77 bytes, más
4 bytes de cabecera de extensión. La oferta del cliente ocupa 1 + 4 bytes.
Las firmas ECDSA tienen longitud variable. Los valores son contadores de
s_client, no bytes de Ethernet/IP/TCP.

Solo son muestras funcionales; no permiten concluir diferencias de rendimiento.
Los CSV y logs están en `artifacts/results/`. Las muestras Merkle registran el
hash del parche concreto usado; después se añadió también la exclusión de DANE
y se repitió la suite completa. No se ha ejecutado un estudio estadístico ni
probado el grupo híbrido opcional. El ahorro de tamaño mediante certificados
compactos sigue sin implementar: esta etapa añade comprobación y bytes a X.509.
