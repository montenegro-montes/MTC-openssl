# Host installation and dependency checks

The host runs the Bash launchers, Python orchestration and plots. It requires
Bash, Python **3.10 or newer**, Git, standard Unix utilities, Docker with the
**Compose v2 plugin** (`docker compose`), and Matplotlib for plotting workflows.
Python requirements are declared in `requirements-host.txt`; pip resolves its
transitive dependencies (including NumPy). This is not a frozen scientific environment.

On Debian/Ubuntu, install the host tools explicitly (administrator access needed):

```sh
sudo apt-get update
sudo apt-get install bash git coreutils grep sed gawk python3 python3-venv python3-pip
python3 --version
```

If the distribution supplies Python older than 3.10, install a supported Python
before proceeding. Install Docker Engine and its Compose v2 plugin using the
instructions for your distribution, or Docker Desktop on macOS. Package names
for Docker differ by distribution/repository; do not mix incompatible Docker
packages. Docker must be running and accessible to the user running the lab.
A Docker CLI alone does not establish daemon access. Check the selected Docker
context and Linux socket permissions if access fails.

From the repository root, create an isolated host environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-host.txt
bin/base/mt-doctor
```

Activate `.venv` in each new shell. The launchers use `python3` from `PATH`;
installing Matplotlib in a different interpreter will not satisfy their checks.
The checker imports the non-interactive Agg backend, so no graphical desktop is
required. Nothing is installed automatically or with implicit sudo.

`bin/base/mt-doctor --offline` checks executable availability, Python version and
the plotting import without invoking Docker. A normal check additionally checks
Compose and daemon access, with a 15-second timeout for each command. All detected
missing dependencies are reported together and cause a nonzero exit code.
`--core` omits plotting requirements for image/container management.

The shared launcher preflight runs host checks before configuration/output writes
(except help/list/show). Existing Docker gates additionally check Compose/daemon
access before Docker actions. This covers the main preparation, protocol,
performance, scaling, network and container launchers sourcing
`bin/lib/docker-preflight.sh`. Direct Python scripts and hand-written `docker run`
commands bypass this integration: run the doctor yourself before those workflows.

OpenSSL with MTC/native instrumentation, liboqs, oqs-provider, compilers and build
tools are installed by the existing Dockerfiles. tcpdump/tshark belong to the
capture image; network tools belong to the network images. Do not substitute the
host's system OpenSSL for the experimental container binary. Image builds need
network access to package/source repositories. The doctor does not check those
remote services, image contents, fixtures, free-space adequacy or experimental
correctness, and does not build images or generate fixtures.

Once the doctor passes, use the existing explicit preparation workflow:

```sh
bin/base/mt-prepare status
bin/base/mt-prepare run ALL
```

**`run ALL` builds missing images, prepares fixtures and runs their functional TLS
validation.** It is separate from dependency checking and should be invoked only
when ready for that work. Existing fixtures from another machine are not assumed
to be valid merely because their files exist.
