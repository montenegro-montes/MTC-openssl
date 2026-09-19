# Network authentication image

See `campaigns/network_authentication/README.md` for the ordered manual workflow.
Build from this directory as the context, passing an immutable `BASE_IMAGE` ID
for the existing mutual-metrics image. The derived image adds network tools only;
all server-only and mutual cases use the same resulting immutable image ID.

No image was built or Docker/TLS experiment executed during preparation.
