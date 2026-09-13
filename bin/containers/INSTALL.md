# Installation manager

Open `bin/containers/mt-install` for the menu. All execution is manual;
creating this script did not build images or remove resources.

```sh
bin/containers/mt-install list
bin/containers/mt-install show 4
bin/containers/mt-install run 1
bin/containers/mt-install run --count 3
bin/containers/mt-install run ALL
```

Stages: 1 base, 2 compact, 3 profiling, 4 MTC, 5 measurement, 6 network,
7 capture. A stage number rebuilds that image; count/ALL build only missing images
in dependency order and stop on failure. Existing images are not proof of source
freshness or passed scientific tests. Logs go to `.mt-state/install/`. A lock
prevents concurrent installation/cleanup through this launcher; independently
started Docker builds or campaigns are not covered. Inspect a stale lock before
manually removing it.

Docker must already be running. Builds check their local parent images first;
the base build may download its Debian parent. No fixtures or campaigns are run.
Use the menu's Start services option only after the target's fixtures and required
Compose environment variables have been prepared. It delegates to mt-containers,
which checks image availability. Containers are runtime instances, so constructing
images does not mean that all services should be started together.

```sh
# Preview and confirm deletion of lab containers and mt-tls-* images:
bin/containers/mt-install clean
# Also include ALL dangling images in the active Docker context:
bin/containers/mt-install clean --dangling
```

Both commands show exact container/image IDs and require `DELETE LAB`. Lab
containers are identified through lab image references/IDs or known Compose
projects. Stopped and running matches are removed; writable-layer contents are
lost. Bind-mounted fixtures/results, named volumes, networks and build cache are
preserved. Dangling images cannot reliably be attributed to this lab, so that
option explicitly includes other projects' dangling images. Images referenced by
other containers are not force-removed; Docker may refuse their removal. This is
not a global `docker system prune` and does not delete unrelated tagged images.
