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
- Plants-05 semantics
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

The Chromium JSON must come from the same newly generated fixture.

## Local hostname resolution

The driver checks the existing `/etc/hosts` entry and local resolution. It never
modifies this file. If missing, manually add `127.0.0.1 server.mtc.example.com`
once, then rerun step 50. Existing entries are never owned by the workflow.

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
   | Plants-05 MTC validation
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
30 validation-evidence verification, 40 anchor export/check, 50 hostname check,
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
There is no build, package installation, gclient sync, hook execution, or automatic
DEPS/toolchain download. This reconstructs the pinned Chromium and BoringSSL Git
content plus depot_tools, **not a build-ready full Chromium dependency checkout**.
Fetching the upstream histories and checking out sources can be expensive and is
reserved for explicit future execution. Other DEPS, Linux GN configuration,
prerequisites, build and browser validation require separately authorized work.

`doctor` prints OS, architecture, tool presence and free space without invoking
wrappers or installing tools. `reconstruct-plan`, source `plan` and source `status`
perform no reconstruction, download or build.
