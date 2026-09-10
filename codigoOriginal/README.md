# Código original recibido

Esta carpeta conserva material de partida separado de la implementación experimental activa:

- `C/`: implementación Merkle/MTC original y programas de prueba en C.
- `Bash/`: script original de generación de certificados.
- `MTC/`: prototipo MTC independiente recibido, con su configuración, scripts y resultados locales.

El laboratorio activo no modifica estos fuentes. Los Dockerfiles pueden compilar las pruebas C desde esta ubicación, mientras el desarrollo posterior vive en `integration/`, `compact/`, `profiling/` y `mtc/`.

Los archivos `.env`, claves privadas, binarios compilados y símbolos de depuración permanecen excluidos de Git. El contenido de `MTC/output/` debe tratarse como evidencia local del prototipo y no como resultado de las campañas reproducibles actuales.
