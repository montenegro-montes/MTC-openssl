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

## Reset project images

```sh
bin/containers/mt-containers reset-images --dry-run
bin/containers/mt-containers reset-images
```

Also available as option 10 in `mt-containers menu`. The command previews image
tags, warns and asks for confirmation. It removes known project containers and
containers using project images, then removes `mt-tls-*` image tags and prunes
unused untagged (`<none>`) images. Untagged-image pruning applies to the entire
active Docker daemon, including other projects, because an untagged image cannot
reliably be attributed to this repository. Images referenced by other containers
and build cache remain. Unrelated tags on shared images are preserved.

`--yes` explicitly bypasses confirmation. Host fixtures, results and launcher
state remain unchanged; this is an image reset, not a campaign data reset.
Rebuild the required images with `mt-prepare run ALL` or `mt-install` afterward.
