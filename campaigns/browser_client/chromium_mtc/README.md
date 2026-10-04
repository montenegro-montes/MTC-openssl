# Chromium MTC integration

Goal: experimental Chromium integration using the validated BoringSSL MTC port.

Initial milestone:
1. Identify where Chromium configures client-side BoringSSL.
2. Identify SSL_CTX / SSL creation and verification configuration.
3. Determine how to enable experimental MTC negotiation.
4. Configure native trust_anchors (provisional 0xca34) in ClientHello.
5. Confirm the historical private 0xffa7 is not emitted. Do not patch Chromium
   to negotiate the old laboratory codepoint; this is not a final IANA assignment.

Out of scope for this milestone:
- MTC certificate verification
- Chromium certificate policy integration
- trust-anchor retry
- resumption
- client authentication
- performance campaigns

## Isolated browser fixture (`server.mtc.example.com`)

Chromium rejects internal or non-unique hostnames during normal certificate
verification. In particular, the earlier browser-only hostname `server.test`
results in `ERR_CERT_NON_UNIQUE_NAME`.

For browser interoperability, use `server.mtc.example.com`.

The hostname is resolved locally to loopback through `/etc/hosts`; no public DNS
record or external network service is required.

`--server-hostname` defaults to `server` in the shared MTC workflow. It sets only
leaf 0's CN and DNS SAN, and both `s_client -servername` and
`-verify_hostname` during validation. Other leaves retain `member-N.lab`.

The following MTC properties remain unchanged:
- draft-06 MTC semantics
- CA and registry IDs
- log and serial-number rules
- landmark semantics
- trust-anchor ID semantics
- SHA-256 Merkle construction
- ECDSA-P256 profile for the initial browser fixture
- N=16 for the initial browser interoperability case

**Always use a new output directory.**

`populate` contains:

```python
if cert.exists():
    continue
```

Therefore, an existing certificate is not reissued merely because a different
hostname was supplied. Do not reuse or edit existing artifacts.

## Generate the Chromium browser fixture

```sh
cd ~/Desktop/MT

BROWSER_HOSTNAME="server.mtc.example.com"
BROWSER_FIXTURE="artifacts/mtc/browser-server-mtc-example-com-ecdsa-p256-n16-$(date -u +%Y%m%dT%H%M%SZ)-$$"

python3 campaigns/browser_client/chromium_mtc/fixtures.py generate \
  --output "$BROWSER_FIXTURE" \
  --server-hostname "$BROWSER_HOSTNAME" \
  --execute
```

## Validate the fixture

```sh
python3 campaigns/browser_client/chromium_mtc/fixtures.py validate \
  --fixtures "$BROWSER_FIXTURE" \
  --output "${BROWSER_FIXTURE}-validation" \
  --server-hostname "$BROWSER_HOSTNAME" \
  --execute
```

Expected leaf-0 identity:

```text
CN  = server.mtc.example.com
SAN = DNS:server.mtc.example.com
```

## Export the Chromium trust configuration

```sh
CHROMIUM_JSON="${BROWSER_FIXTURE}-chromium.json"

test ! -e "$CHROMIUM_JSON" && \
python3 campaigns/browser_client/chromium_mtc/export_chromium_anchor.py \
  --trust "$BROWSER_FIXTURE/batch16/mtc/ecdsa-p256/trust.bin" \
  --output "$CHROMIUM_JSON"
```

The Chromium JSON is exported from the fixture's typed MTB2 trust bundle and
records `"source_format": "MTB2"`. It must come from the same newly generated
fixture.

## Local hostname resolution

Step 50 verifies an existing correct `/etc/hosts` entry. If the hostname is
absent, it shows and appends `127.0.0.1 server.mtc.example.com` using `sudo tee -a`.
It refuses to modify conflicting entries and reports them for manual correction.
It then rechecks the file and requires local resolution exclusively to
`127.0.0.1`. Repeated runs do not add duplicates; cleanup preserves the entry.

The browser can then access:

```text
https://server.mtc.example.com:4433/
```

No `--host-resolver-rules` Chromium flag is required.

## Chromium-specific fixture wrapper

`campaigns/browser_client/chromium_mtc/fixtures.py` is the
Chromium-specific entrypoint.

For the initial browser experiment:

```text
profile     = ecdsa-p256
tree size   = 16
mode        = landmark
hostname    = configurable through --server-hostname
```

It delegates generation and validation to the shared MTC workflow and does not
duplicate MTC issuance or verification code.

## Expected browser interoperability flow

```text
Chromium
   |
   | HTTPS to server.mtc.example.com:4433
   |
   | ClientHello
   | trust_anchors = 32473.101.2.1.1
   v
OpenSSL/MTC server
   |
   | EncryptedExtensions
   | selected trust anchor = 32473.101.1.1.1
   |
   | MTC landmark certificate
   | CertificateVerify
   | Finished
   v
Chromium
   |
   | draft-06 MTC validation
   | hostname = server.mtc.example.com
   | Finished
   v
HTTPS application data
```

A clean positive result requires:
- `server.mtc.example.com` resolves to `127.0.0.1`
- certificate CN/SAN matches `server.mtc.example.com`
- ClientHello carries provisional `trust_anchors` extension `0xca34`
- requested trust-anchor ID is `32473.101.2.1.1`
- server selects `32473.101.1.1.1`
- historical private `0xffa7` is not emitted
- CertificateVerify is present
- server Finished is present
- client Finished is present
- Chromium loads the HTTPS response
- no `ERR_CERT_*` interstitial is shown

## Existing-build resumable driver

```sh
bin/browser_client/mt-chromium-mtc init
bin/browser_client/mt-chromium-mtc plan
bin/browser_client/mt-chromium-mtc resume
bin/browser_client/mt-chromium-mtc status
# Stop only the labelled workflow container; preserve fixtures/results/hosts:
bin/browser_client/mt-chromium-mtc cleanup
```

`show STEP` displays implementation/commands; `run STEP` executes one step.
Steps: 00 preflight, 10 existing Chromium detection, 20 fixture selection,
30 validation-evidence verification, 40 anchor export/check, 50 hostname configuration,
60 positive server start. `resume` skips every stage with an existing `.done` marker. Use `run STEP`
to explicitly recheck a completed stage; `status` checks container state. Stopped/foreign containers require inspection;
they are never silently replaced. No retries of TLS samples occur.

Paths persist in `.mt-state/chromium-mtc/paths.env`; no inherited terminal
variables are needed. `chromium.json` records checkout commits, executable hash,
and debug/component flags (component flag falls back to generated base Ninja
compile definitions). Checkout commits describe the current checkout, not proof
that the executable was built from a clean tree. The small launcher executable's
hash is not a hash of all component libraries.

Step 20 selects the known ECDSA-P256 N=16 fixture. If missing it stops: use the
explicit generation command above with a fresh timestamped output, validate it,
then update the persisted FIXTURE/VALIDATION/ANCHOR paths. No generation is
implicit. Step 30 verifies all fixture hashes against successful existing TLS
validation and checks the hostname/profile/size; it does not rerun TLS. Steps
20–50 do not need Chromium. Step 40 preserves and checks an existing JSON against
the trust configuration, or exports to a new path.

Step 60 pins the image ID from the validation evidence, uses `--pull never`,
read-only fixtures, and publishes only `127.0.0.1:4433`. It records container ID
and a unique `artifacts/results/chromium-mtc-validation-<timestamp>-<suffix>/`
directory. `server.log` is written directly there for the container lifetime.
Readiness checks OpenSSL's ACCEPT marker, not browser interoperability.
No browser is launched and no browser profiles are created. Cleanup removes
only the container labelled with this workflow state directory; it preserves
logs, all artifacts and the pre-existing hosts entry.

## Deterministic source reconstruction

`reconstruct-plan` prints upstream pins, preserved custom commits and exact Git
source tree hashes from `versions/chromium-mtc.env`. Tree hashes are authoritative
for source content; commit IDs additionally preserve history and Chromium's exact
BoringSSL gitlink. The readable format-patches remain unchanged, but reconstruction
imports incremental bundles instead of replaying `git am` (which can change IDs).

Both bundles require the corresponding upstream base commit and its reachable
objects. They contain only custom history, not the complete upstream repository.
Verify integrity from this campaign directory:

```sh
shasum -a 256 -c patches/SHA256SUMS
shasum -a 256 -c source-bundles/SHA256SUMS
# Run in repositories already containing the respective base histories:
git -C /path/to/chromium bundle verify /absolute/path/to/source-bundles/chromium-mtc.bundle
git -C /path/to/boringssl bundle verify /absolute/path/to/source-bundles/boringssl-mtc.bundle
```

The separate source interface defaults to `$HOME/chromium-mtc-rebuild`.
Use optional `--dest ABSOLUTE_PATH` before or after the subcommand to override it:

```sh
bin/browser_client/mt-chromium-mtc reconstruct-plan
bin/browser_client/mt-chromium-mtc reconstruct-source plan
bin/browser_client/mt-chromium-mtc reconstruct-source status
# Future server only: explicitly run each step in order; 110–130 download sources.
bin/browser_client/mt-chromium-mtc reconstruct-source run 100
# Then individually run 110, 120, 130, 140, 150, 160.
# Optional override (also accepted after run 100):
bin/browser_client/mt-chromium-mtc reconstruct-source --dest /srv/mtc-source plan
```

| Step | Operation |
| --- | --- |
| 100.verify-reconstruction-inputs | Verify patch/bundle SHA-256 and advertised commit tips; claim empty destination. |
| 110.prepare-depot-tools | Fetch and checkout pinned depot_tools; do not invoke its wrappers. |
| 120.prepare-chromium-base | Fetch upstream Chromium base history, checkout and verify base tree. |
| 130.prepare-boringssl-base | Fetch upstream BoringSSL base history, checkout and verify base tree. |
| 140.import-preserved-commits | Verify bundle prerequisites, import exact objects and verify patched trees. |
| 150.checkout-patched-source | Checkout preserved commits and verify source. |
| 160.verify-source-trees | Recheck exact HEADs, tree hashes, clean source and BoringSSL gitlink. |

The first run of step 100 creates an absent destination automatically and writes
`.mtc-source-owner.json`, identifying the `chromium-mtc-source-v1` workflow and
binding the canonical path and version metadata. An empty directory can also be
claimed; an existing matching owned destination is reused. A non-empty directory
without a matching ownership marker is refused and never deleted. Unrelated
content is never overwritten. `plan` and `status` do not create the destination;
both print the resolved default or override path.
Unexpected non-empty destinations, symlink source paths, and overlaps with MT,
`~/Desktop/chromium-mtc` or `~/Desktop/depot_tools` are rejected. Each step requires
all earlier completion markers and uses a separate destination lock. Existing
source repositories must match the expected state; no forced checkout or cleanup
is performed. Interrupted fetch/checkouts may require manual inspection before
retrying. Status reports recorded completion, not fresh validation; explicitly
run 160 to revalidate. Input checks run before every source execution.

Normal `resume` retains only the existing positive interoperability steps 00–60;
it cannot reach any reconstruction stage. Source stages have no resume command.
The reconstruction namespace performs no build, package installation, gclient
sync, hook execution, or automatic DEPS/toolchain download. This reconstructs the pinned Chromium and BoringSSL Git
content plus depot_tools, **not a build-ready full Chromium dependency checkout**.
Fetching the upstream histories and checking out sources can be expensive and is
reserved for explicit execution. The separate preparation and build interfaces
below handle DEPS, Linux prerequisites, GN and compilation. Browser validation
remains a separate activity.

`doctor` prints OS, architecture, tool presence and free space without invoking
wrappers or installing tools. `reconstruct-plan`, source `plan` and source `status`
perform no reconstruction, download or build.


## Explicit Ubuntu 24.04 x86_64 build preparation

Source reconstruction through 160 has been manually validated on the server
(user-reported). The new preparation/build path has only been checked statically
and through print-only interfaces on macOS; real sync, hooks, installation, GN
and compilation still require server validation.

All commands default to `$HOME/chromium-mtc-rebuild` and accept optional
`--dest ABSOLUTE_PATH` before or after the action. Plan/status are portable and
read-only; execution rejects platforms other than Ubuntu 24.04 x86_64.

```sh
bin/browser_client/mt-chromium-mtc prepare-build plan
bin/browser_client/mt-chromium-mtc prepare-build status
bin/browser_client/mt-chromium-mtc prepare-build run 170
bin/browser_client/mt-chromium-mtc prepare-build run 180
bin/browser_client/mt-chromium-mtc prepare-build run 190
bin/browser_client/mt-chromium-mtc prepare-build run 200
# Only if packages are missing: explicitly install with Chromium's own script.
# It may request sudo; this action is never inferred from a failed check.
bin/browser_client/mt-chromium-mtc prepare-build install-deps
# After installation, explicitly rerun 200, then continue:
bin/browser_client/mt-chromium-mtc prepare-build run 210
bin/browser_client/mt-chromium-mtc prepare-build run 220
```

| Stage | Explicit action |
| --- | --- |
| 170.verify-reconstructed-source | Check preserved Chromium/BoringSSL HEADs and trees, BoringSSL gitlink, clean tracked files/index and pinned depot_tools. |
| 180.prepare-chromium-checkout-layout | Write a matching `.gclient` in the reconstruction root; refuse conflicting configuration. Never replace `src`. |
| 190.sync-pinned-deps | Run pinned `depot_tools/gclient sync --nohooks --noprehooks` from the reconstruction root. Downloads dependencies without running hooks. |
| 200.check-linux-build-dependencies | Run `src/build/install-build-deps.sh --quick-check`; fail on missing packages without installing anything. |
| 210.configure-linux-release | Initialize pinned depot_tools with `ensure_bootstrap`, verify its Python, then run `gclient runhooks` and `gn gen out/mtc-release` from `src`. Hooks download/setup toolchains; GN generates build files, without compiling Chromium. |
| 220.verify-build-configuration | Reverify source, layout, exact args, generated `build.ninja` hash and absence of recorded build attempts/known compilation artifacts. |

The `.gclient` is exactly:

```python
# Owned by the Chromium MTC reconstruction workflow.
solutions = [{
    'name': 'src',
    'url': 'https://chromium.googlesource.com/chromium/src.git',
    'managed': False,
    'deps_file': 'DEPS',
    'custom_deps': {'src/third_party/boringssl/src': None},
}]
target_os = ['linux']
target_os_only = True
```

`managed=False` leaves the reconstructed Chromium HEAD authoritative. Its
preserved DEPS supplies dependency revisions; no revision override requests an
unpublished custom commit from upstream. `custom_deps=None` excludes BoringSSL
from synchronization: its DEPS pin names the upstream base whereas the patched
Chromium gitlink names the preserved custom commit. The existing BoringSSL
checkout is kept in place. There is no force/reset/delete operation or fallback
that overwrites it. Exact HEADs, trees, tracked content and the gitlink are checked
before and after synchronization, including after a failed sync. A mismatch
fails closed for manual inspection. Untracked/ignored dependency and output
files are not claimed to be covered by the two Git tree hashes.

All tool commands prepend the reconstructed pinned depot_tools to PATH and set
`DEPOT_TOOLS_UPDATE=0`. gclient and autoninja use absolute paths to that checkout.
Wrappers may bootstrap their pinned tools during explicit execution. The Linux
package list belongs to Chromium, not this driver. `install-deps` invokes
`build/install-build-deps.sh`, then its `--quick-check`; it invalidates stages
200–220, which must be run explicitly again. No plan/status or other namespace
installs packages. The upstream workflow reference is
[Chromium Linux build instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/build_instructions.md);
actual commands/flags were checked against the local pinned scripts.

The complete `src/out/mtc-release/args.gn` is:

```gn
is_debug = false
is_component_build = false
symbol_level = 1
use_remoteexec = false
```

The last two settings retain the known-good checkout's symbol level and local
execution choice. No additional MTC feature flag was present in its `args.gn`;
MTC functionality remains in the preserved source patches. The Linux x86_64
host supplies the native target defaults. A non-empty output directory must
already carry matching ownership evidence in `.mtc-build-state/output-owner.json`;
conflicting args are refused rather than overwritten.

## Explicit compilation and provenance

```sh
bin/browser_client/mt-chromium-mtc build plan
bin/browser_client/mt-chromium-mtc build status
# The only driver interface that compiles Chromium:
bin/browser_client/mt-chromium-mtc build run chromium
```

The last command invokes exactly the equivalent of:

```sh
cd "$HOME/chromium-mtc-rebuild/src"
"$HOME/chromium-mtc-rebuild/depot_tools/autoninja" -C out/mtc-release chrome
```

It requires current successful stages 170–220, the reconstruction ownership and
160 record, matching `.gclient`, exact sources/depot_tools, output ownership,
matching args and the generated Ninja file. It reruns the package quick-check
before compilation. Missing output or stale prerequisites cause failure, never
implicit sync, install, hooks or GN generation.

Preparation evidence binds the driver SHA-256, version pins, destination, GN args,
layout and source verification marker timestamp. Rerunning a preparation stage
invalidates its own and later evidence. Preparation/build share reconstruction's
lock, so these driver operations cannot race. Status reports recorded evidence,
not fresh verification of files or external manual activity. Stage 220's
pre-compilation check is limited to workflow attempts and known artifact names;
it cannot prove that no external compilation has ever occurred.

A successful future build records `.mtc-build-state/build-result.json`: UTC time,
Chromium/BoringSSL commits and trees, depot_tools commit, GN args, exact command,
working directory, executable path and streamed SHA-256. A separate attempt
record distinguishes started/failed/successful attempts; an older success record
is retained if a later attempt fails. No large artifacts are archived. Once a
build has been attempted, stage 220 refuses to certify a fresh pre-compilation
state; existing current preparation evidence permits an explicit build retry.

Normal `resume` remains limited to interoperability stages 00–60. Reconstruction
100–160 is unchanged. Neither reconstruction nor preparation can dispatch
compilation. `build plan/status` cannot build, and missing output never triggers
an automatic build.


Stage 210 explicitly runs `depot_tools/ensure_bootstrap` before hooks/GN. With
`DEPOT_TOOLS_UPDATE=0`, running gclient alone does not initialize the hermetic
Python required by the GN wrapper. `ensure_bootstrap` downloads bootstrap tools
without updating the depot_tools Git revision; the driver verifies that revision
again and checks `python3_bin_reldir.txt` and the Python executable. This runs only
on explicit stage 210, never from plan/status/resume. External command failures
stop with a concise error rather than a Python traceback. A Git-version
recommendation is separate from a missing bootstrap and is left visible.

## Browser credential discovery and functional battery

This explicit namespace is independent of interoperability `resume`, reconstruction
and build preparation. It never builds Chromium, fetches sources, syncs dependencies
or installs a trust anchor. Python's `cryptography` package, OpenSSL, Docker and an
existing patched Chromium are prerequisites; missing tools are not installed.

```sh
bin/browser_client/mt-chromium-mtc browser-validation plan
bin/browser_client/mt-chromium-mtc browser-validation credentials
bin/browser_client/mt-chromium-mtc browser-validation status
bin/browser_client/mt-chromium-mtc browser-validation run all
bin/browser_client/mt-chromium-mtc browser-validation run mtc-positive
bin/browser_client/mt-chromium-mtc browser-validation cleanup
```

Optional `--chromium /absolute/executable` selects an existing browser;
`--timeout 60` bounds each invocation (allowed range 5–300 seconds). Default
executable candidates cover the reconstructed Linux release and the existing
macOS `.app` layout. There is no build fallback. The recorded executable hash
covers the executable/launcher, not all shared libraries in a component build.

Credential selection searches only `artifacts/mtc/*/manifest.json`, and
`server.pem` fixtures beneath `artifacts/x509` and `artifacts/cert-chain-scaling`.
It does not depend on the historical fixture basename. Candidates are ranked by
complete browser-specific evidence, complete evidence, browser-specific path,
timestamp and lexical path. All candidates and rejection/selection reasons are
recorded, including discovery audits before a generation fallback is attempted.

MTC validation checks the manifest hostname `server.mtc.example.com`, ECDSA P-256,
N=16, log 1/member 0, certificate/key match, leaf SAN/KU/EKU/validity, local hash
inventory, checkpoint signatures, inclusion proof, empty landmark signatures,
serial range, requested group `32473.101.2.1.1` and selected ID
`32473.101.1.1.1`. Existing functional evidence must PASS; recorded fixture hashes
must match exactly. Existing failure reports disqualify a candidate. Without
functional evidence a candidate must still pass the local cryptographic checks;
complete evidence is preferred. No reused fixture is modified.

If none is valid, `fixtures.py generate` and `fixtures.py validate` are explicitly
called with the canonical hostname into fresh timestamped directories. A failed
generation/validation stops preparation. The image must already exist; no image
build is attempted. An anchor is reused only when its full content equals the
current draft-06 exporter/parser output, including trust-file hash and subtree
hashes. Otherwise a new anchor is exported into the new result directory; old
anchors are preserved.

X.509 validation checks the actual SAN, P-256 public key, non-CA leaf, Digital
Signature KU, serverAuth EKU, validity, private-key match, CA root and OpenSSL
chain/hostname verification. Available fixture hash manifests are checked. The
existing generic chain builder fixes SAN to server/localhost, so the browser
fallback uses a small P-256 direct-root certificate generator with the required
web identity, rather than modifying unrelated campaign PKI. Its new keys and
certificates are generated only when no existing candidate validates.

Trust is audited separately: macOS uses local-only `security verify-cert` with
SSL hostname policy and the normal keychain trust search (no supplied trust-root
override). Linux checks the exact root fingerprint and SSL CA trust in Chromium's
user NSS database, respecting legacy `~/.pki/nssdb` or the XDG location. The
positive browser case is the final trust check. If trust is not established,
credentials/status print the exact manual trust-install command and execution
stops. No command automatically modifies the Keychain, NSS database or system
trust store. `certutil` is needed for Linux trust auditing/manual installation.

The five cases are `mtc-positive`, `mtc-no-trust`, `mtc-bad-merkle`,
`mtc-bad-serial` and `x509-positive`. A single requested MTC negative case first
executes its positive control in the same run. `run all` executes each case once.
The bad-Merkle anchor flips one byte in the trusted subtree covering leaf 0. The
bad-serial anchor increments both range endpoints and their hexadecimal forms,
preserving range length. Positive anchors remain byte-for-byte unchanged.

All cases use TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, no tickets, server-only
validation and the same pinned OpenSSL image/server behavior on loopback 4433.
Each uses a fresh temporary Chromium profile, `--headless=new`, DOM dump and
NetLog. A resolver rule maps only the canonical hostname to loopback without
changing hostname verification or `/etc/hosts`. Certificate bypass flags are
never used.

An occupied port blocks the run; another workflow's container is not removed.
If the old interoperability server occupies it, stop it explicitly using its
own lifecycle command before starting this battery:

```sh
bin/browser_client/mt-chromium-mtc cleanup
bin/browser_client/mt-chromium-mtc browser-validation run all
```

Every credential audit/run writes a fresh
`artifacts/results/chromium-browser-validation-<UTC>-<unique>/` directory. It
contains candidate audits, `credentials.json`, and, for executed cases, commands,
Chromium stdout/stderr, NetLog, server TLS transcript, derived anchors and
`result.json`; a battery also writes `summary.json`. Blocked cases are explicitly
INCONCLUSIVE/not executed. Synthetic unit-test artifacts live only in temporary
directories, never in these campaign result roots.

Classification links NetLog sources to the unique target URL and combines
handshake messages, TLS parameters, HTTP headers, DOM response and server
Certificate/CertificateVerify/Finished evidence. MTC positive and mutated-anchor
cases also require requested/selected TAI evidence. Chromium exit code alone
never establishes PASS. Negatives require a successful positive control and
certificate rejection evidence with no client Finished or accepted HTTP; an
earlier negotiation failure or incomplete evidence remains INCONCLUSIVE.
Headless suitability is established only by a successful real positive case,
not by `--headless` being accepted on the command line.

Containers carry a per-run ownership label and use `--pull never`. Normal case
cleanup terminates only the launched browser process group, removes its temporary
profile and removes its labelled server; all logs and anchors remain. Explicit
cleanup handles abandoned labelled containers. Orphan profiles are reported for
manual process-ownership inspection instead of killing a potentially recycled PID
or deleting an in-use profile. Plan/status launch no browser/server; status only
reads results and re-audits the selected root's current trust.

Focused cheap tests:

```sh
bash -n bin/browser_client/mt-chromium-mtc
python3 -m unittest tests/test_chromium_mtc_workflow.py -v
git diff --check
```


Credential date validation supports both current `cryptography` UTC properties
and older versions exposing naive UTC dates. Validator API/type/import failures
stop discovery without generation; they do not disqualify all existing fixtures.
The selected X.509 CA remains at the fixture's `root.pem`. Every successful
credential preparation also preserves its public certificate as
`x509-root-ca.pem` in the new result directory, with source/copy SHA-256 and a
root self-signature verification command in `credentials.json`. The root must
be a self-issued CA and pass OpenSSL `verify -check_ss_sig`; this cryptographic
check remains separate from browser/platform trust. Private CA keys are never
copied into the result directory.


## Linux developer Chromium: AppArmor sandbox preparation

Ubuntu/Linux may restrict unprivileged user namespaces, preventing developer
Chromium builds from creating their sandbox. After building Chromium, configure
`CHROMIUM_SRC` in `.mt-state/chromium-mtc/paths.env`, then run:

```sh
bin/browser_client/mt-chromium-mtc sandbox-setup
bin/browser_client/mt-chromium-mtc sandbox-status
```

The setup applies only on Linux when
`/proc/sys/kernel/apparmor_restrict_unprivileged_userns` equals `1`. It targets
exactly the resolved `CHROMIUM_SRC/out/mtc-release/chrome`, without wildcards.
It installs `/etc/apparmor.d/mtc-chromium-<path-sha256-prefix>` after syntax
validation, using explicit `sudo` commands when needed. An identical installed,
loaded profile is reused. Different existing content is preserved and rejected.
`doctor` and the build-preparation menu expose the check; setup is explicit.
Both commands explicitly use `sudo cat` if kernel policy state is not readable
by the current user; the driver itself need not run as root. They reject another
explicit attachment to the same executable found in /etc/apparmor.d before
installing/loading a policy. Conflicting files are reported and left unchanged.

The profile uses `flags=(unconfined)` and `userns,` to permit this developer
executable to create Chromium's own sandbox. AppArmor remains enabled, the
system-wide restriction is unchanged, and no browser sandbox bypass is added.
macOS is unaffected. Re-run setup if the configured executable path changes.
This checks policy presence, not a live browser sandbox launch.
See [Chromium's AppArmor guidance](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md).


### Explicit MTC fixture reuse in the controlled driver

`mt-chromium-mtc browser-validation run ...` (delegated to
`mt-chromium-tests`) and setup's `browser-validation credentials` pass
`--mtc-fixture` and `--mtc-validation` from
`.mt-state/chromium-mtc/paths.env`. Steps 20/30 must already have selected and
checked the fixture and its successful functional validation evidence.
Missing or stale evidence fails; there is no MTC discovery or generation fallback.
The fast path checks the complete recorded fixture hashes, profile, hostname,
landmark identity, certificate validity and image provenance, and records
`origin=reused-prevalidated` plus the validation-file SHA-256. Anchor checking
and export remain unchanged.

Direct `browser_validation.py` invocation without both options retains its
existing discovery/cryptographic validation/generation behavior. X.509 discovery,
PCAP and measurement routes are unchanged. The evidence is local trusted input;
hash checks detect stale fixture data, not an attacker rewriting both data and
its validation evidence.
