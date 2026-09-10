# Código original recibido

Esta carpeta conserva material de partida separado de la implementación experimental activa:

- `C/`: implementación Merkle/MTC original y programas de prueba en C.
- `Bash/`: script original de generación de certificados.
- `MTC/`: prototipo MTC independiente recibido, con su configuración, scripts y resultados locales.

El laboratorio activo no modifica estos fuentes. Los Dockerfiles pueden compilar las pruebas C desde esta ubicación, mientras el desarrollo posterior vive en `integration/`, `compact/`, `profiling/` y `mtc/`.

Los archivos `.env`, claves privadas, binarios compilados y símbolos de depuración permanecen excluidos de Git. El contenido de `MTC/output/` debe tratarse como evidencia local del prototipo y no como resultado de las campañas reproducibles actuales.

## Papel durante la creación del proyecto

No ejecute esta carpeta como punto de entrada del laboratorio actual. La imagen
base copia `C/crypto/` y los programas `C/*tests.c`, los compila dentro del
contenedor y conserva el material recibido sin editarlo:

```sh
docker compose -f docker/compose.yaml build
```

Después de construir, puede comprobar qué pruebas quedaron instaladas:

```sh
docker run --rm --network none mt-tls-lab:local \
  sh -c 'ls -l /opt/mt/bin/merkle_tests /opt/mt/bin/mtc_tests /opt/mt/bin/merkle_mtc_tests'
```

La integración activa se construye mediante [el README raíz](../README.md) y
[las definiciones Docker](../docker/README.md). El prototipo de `MTC/` conserva
su propio `README.TXT` solo como documentación histórica; sus comandos, imagen,
algoritmos y resultados no sustituyen el flujo reproducible actual.

## Comprobación antes de publicar

```sh
git status --short
git ls-files codigoOriginal
git check-ignore codigoOriginal/MTC/config/.env
git check-ignore codigoOriginal/C/certs/cert1.key
```

Las dos últimas órdenes deben confirmar que el entorno local y las claves están
ignorados. No añada `.DS_Store`, binarios locales, claves privadas ni nuevos
resultados del prototipo.
