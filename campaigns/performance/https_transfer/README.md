# Transferencia HTTPS con fixtures existentes

Experimento pequeño de transferencia de recursos mediante `openssl s_server -WWW`.
Reutiliza la imagen MTC ya construida y los fixtures N=16, hoja 0, de la campaña
`bin/performance/mt-handshake-performance` (`case_args`, autenticación simple).
Las opciones TLS y la verificación de hostname siguen también
`campaigns/validation/protocol_validation/capture.py`. No prepara certificados,
no construye imágenes ni modifica la lógica MTC.

Matriz fija: `ecdsa-p256`, `mldsa65` × `x509`, `mtc-landmark`,
`mtc-standalone` × 1 KiB, 10 KiB, 100 KiB, 1 MiB. Cada celda tiene 5 warmups y
30 medidas: 120 warmups y 720 medidas, 840 conexiones en total.
Para cada perfil y tamaño se ejecutan primero 5 rondas de warmup y después 30
rondas medidas. Cada ronda visita los tres modos una vez, con rotación determinista:
`x509 → mtc-landmark → mtc-standalone`, después
`mtc-landmark → mtc-standalone → x509`, después
`mtc-standalone → x509 → mtc-landmark`; se repite el patrón.
La rotación y `run` reinician en 1 en cada fase y combinación perfil/tamaño.
No hay aleatorización. Los comandos conservan el mismo puerto: se inicia y detiene
el servidor en cada muestra, fuera del intervalo cronometrado, con un log de
servidor por muestra. Los warmups no mantienen caliente un proceso servidor
persistente; este cambio de ciclo de vida debe considerarse al comparar con la
ejecución anterior agrupada. Cada muestra crea un proceso `s_client` y una conexión nueva.
TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384`, servidor sin tickets, cliente
`-no_ticket`, sin sesiones importadas ni certificado de cliente. Hostname `server`.

El GET se envía después de observar en los diagnósticos de `s_client` la
verificación satisfactoria, TLS/cipher esperados y X25519. Usa HTTP/1.0 con
`Connection: close`. Recibe hasta EOF y exige HTTP 200, salida cero y cuerpo
idéntico al recurso completo. Un fallo queda en el CSV y produce salida global
no cero; no hay reintentos. El timeout es 90 segundos por muestra.

El origen temporal (`start = time.perf_counter()` en `sample`) se toma antes de
`subprocess.Popen`, incluso antes de crear los buffers. `ttfb_ms` termina cuando
Python detecta por primera vez `HTTP/1.` en stdout acumulado después de enviar el
GET; no es una marca del primer byte en la red. `total_ms` termina al drenar
stdout y stderr hasta EOF, antes de `process.wait()` y de validar el cuerpo.
En caso de excepción, `total_ms` se toma al capturarla.
Ambos incluyen arranque del proceso, TCP, TLS, comunicación por pipes y coste del
observador. **No son tiempos nativos de handshake ni tiempos de transferencia
pura**. `handshake_ok` indica que se observó la negociación/verificación antes del
GET; `body_ok`, estado HTTP y returncode deben comprobarse por separado.
`response_body_bytes` excluye cabeceras. `run` empieza en 1 en cada fase/celda;
`is_warmup` identifica las filas que deben excluirse del análisis principal.

## Ejecución manual

Desde la raíz del repositorio, con Docker disponible y la imagen
`mt-tls-mtc:local` ya preparada, ejecutar explícitamente:

```sh
docker run --rm --network none \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD:/repo:ro" -v "$PWD/artifacts/results:/results" \
  --entrypoint python3 mt-tls-mtc:local \
  /repo/campaigns/performance/https_transfer/run.py \
  --mtc-root /repo/artifacts/mtc/n16-x25519-20260924T070200Z \
  --output /results/https-transfer-$(date -u +%Y%m%dT%H%M%SZ)-$$ \
  --execute
```

La raíz anterior es la indicada por `MTC16` en `.mt-state/cert-scaling/paths.env`
al preparar este runner. Si cambia, sustituirla por otra raíz existente con
`population/<perfil>/{0.pem,0.key,ca.pem}` y
`batch16/mtc/<perfil>/{manifest.json,landmark-0000.pem,standalone-0000.pem,trust.bin,authority.bin}`.
La carpeta host `artifacts/results` debe existir. El puerto 4433 se usa solo en
loopback dentro del contenedor aislado; no se publica. Sin `--execute` únicamente
se imprime la matriz, sin crear resultados ni abrir conexiones desde el runner.

Los resultados quedan en `artifacts/results/https-transfer-<fecha>-<pid>/`:
`samples.csv`, `commands.json`, `logs/` y `objects/`. Los cuatro recursos
`1k.bin`, `10k.bin`, `100k.bin`, `1m.bin` se crean únicamente al ejecutar, repitiendo
los bytes 0..255 hasta el tamaño exacto. No se sobrescribe una salida existente.

Limitaciones: transferencia local en un único contenedor, cachés del sistema
sin vaciar, orden fijo y tiempos afectados por procesos/pipes. No hay PCAP ni
agregados. Se requiere que la imagen existente emita los diagnósticos TLS habituales
y `MTC verification: OK`; su ausencia falla de forma cerrada. Solo se han
realizado comprobaciones estáticas: ejecución TLS/HTTP **NOT CHECKED — requires
execution**. No representa una validación experimental completada.

El cliente no silencioso puede escribir el diagnóstico terminal `closed\n` en
stdout. El parser lo separa únicamente si son exactamente los siete bytes
posteriores al tamaño esperado; sigue comparando cada byte del cuerpo y rechaza
cualquier otro exceso. El diagnóstico separado queda en el log. En muestras
fallidas se conserva además `logs/*.stdout.bin` para inspeccionar la respuesta.
Esta separación depende del comportamiento de la CLI, no de un framing HTTP
independiente. Los resultados anteriores no se reparan ni se reclasifican.
