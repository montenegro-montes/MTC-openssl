# Docker prerequisites

`docker-preflight.sh` is sourced by the four Bash launchers. It is not an entrypoint
and does not start Docker, build images, start containers or delete data.

Before a Docker-dependent action it checks the CLI, daemon, Compose when needed,
and required local images. Build steps check parent images rather than requiring
the image they are about to build. Image-chain repair can prepare its own images.
Compose up/run checks the target's configured images, then lets Compose create
its containers. Shell requires an existing running container and a healthy status
when a healthcheck exists. Logs require an existing container, including stopped
containers useful for debugging. Configuration errors report missing Compose
variables without a Python traceback.

Help, menus, saved status, plan/show, static-only analysis, `mt-archive` and
`mt-check-publication` do not require Docker. They perform no Docker operations.
Protocol offline checks still require Docker because their launcher runs OpenSSL
inside the existing image. Each stage in a batch checks its own prerequisites.
Missing prerequisites stop execution before the scientific command is launched;
no artifacts are regenerated and no resources are started automatically.

These checks cannot prevent Docker or a container failing after the check. Original
campaigns retain their own checks for frozen image IDs, fixtures and configuration;
an image's presence is not evidence of scientific validity.
