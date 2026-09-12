# PCMA Stage A.2 — Compact Client-State Advertisement Evaluation

This laboratory is **prepared for manual execution**. Preparing it does not run
Stage A, Stage A.2, Stage B, TLS, Docker, or a network benchmark. No Stage A.2
experimental findings or GO/NO-GO outcome are claimed.

## 1. Motivation and scientific question

Stage A produced 156 configurations and 156,000 observations. Its important cost
is advertisement overhead: eliminating proof siblings alone does not establish
net communication benefit. Can authenticated Merkle client state be represented
compactly enough to produce consistent net savings across credentials?

The actual Stage-A encoder already omits hashes. Stage A.2 reduces coordinate
and framing overhead rather than claiming savings from removing nonexistent
wire hashes. See the exact reconstruction below.

## 2. What stays fixed

Imports use the existing `campaigns/original_campaigns/pcma/{core,cache,run,workloads}.py` without
editing them. Real MTP1 fixture validation, MTP2 construction/reconstruction,
SHA-256 leaf/parent hashing, duplicate-last odd-tree behavior, LRU/upper-level
learning and eviction, and **69 bytes per stored cache record** remain unchanged.
A root is never inserted as a cached trust anchor. Compact credential, TLS,
OpenSSL and fixture generation code are untouched.

For each access all schemes use the same pre-access keys and local hashes.
The driver checks decoded state equality, byte-for-byte MTP2 equality, and
reconstructed authenticated-state equality. It then accounts cache hits and
updates the cache once, in the same order as Stage A. Selection of an encoding
does not change capacity, learning, or proof opportunity.

## 3. Existing Stage-A advertisement reconstructed

Authoritative code: `campaigns/original_campaigns/pcma/core.py:encode_advertisement` and
`decode_advertisement`; storage: `campaigns/original_campaigns/pcma/cache.py`; measurement phase:
`campaigns/original_campaigns/pcma/run.py:simulate`.

PCA1 is concatenation without padding, using network byte order:

| Field | Bytes | Meaning |
|---|---:|---|
| magic | 4 | ASCII `PCA1`, also identifies version |
| root | 32 | full SHA-256 Compact root, once per advertisement |
| count | 2 | unsigned big-endian number of unique nodes |
| entries | 5K | each: unsigned level (1), unsigned big-endian index (4) |

`A_baseline(K) = len(encode_advertisement(root, keys)) = 38 + 5K`, where K is
the number of unique root-scoped advertised nodes. Empty advertisements cost
38 bytes. Entries sort by `(level,index)`; the original encoder deduplicates
input. Its decoder rejects duplicates, unsorted entries and inconsistent
length. PCA1 does **not** transmit hashes, repeat roots per node, include N,
or contain TLS framing. Hashes and repeated roots occur in the **local
69-byte storage record**, not the PCA1 body. Levels/indices use unnecessarily
wide fixed fields for N <= 1024; level can instead be inferred from an ordinal.
The 38-byte fixed header also matters when little state is reusable.

`baseline` delegates to the actual Stage-A encoder unchanged. The A.2 wrapper
rejects duplicate input and coordinates outside the expected tree, providing
stricter validation without changing any valid cache-state bytes. Unit tests
verify the formula against that encoder for empty, small and complete sets,
including coordinate-only N=1024 cases.

## 4. New exact serialization formats

All new encoders have decoders in `formats.py`. Sizes used in observations are
always `len(encode(...))`, never a size estimate. Define `u(x)` as the byte
length of minimal unsigned LEB128: 1 for 0..127, 2 for 128..16383, 3 for
16384..65535. Integers outside 0..65535 and overlong forms are rejected.

Common PCA2 header, no padding:

```text
ASCII PCA2 [4] | version=1 [1] | encoding mode [1] | root [32] | ULEB128(N)
H(N) = 38 + u(N) bytes
```

N=16/64 have H=39; N=256/1024 have H=40. This experimental version is distinct
from PCA1 and has no TLS extension identifier.

Build the deterministic universe of all non-root coordinates, level-major and
index-minor. Level 0 has N nodes; successive widths are `ceil(previous/2)`.
Let `w_l` be the width at level l. Node `(l,i)` maps to
`j = sum(w_h for h < l) + i`. The inverse scans those same widths. The root is
excluded. `T = sum(w_l for l < depth)`; for power-of-two N, `T=2N-2`.
N=1024 has 2046 positions, 0..2045. No hash is needed to interpret possession.

| Scheme / mode | Body | Exact total bytes |
|---|---|---|
| coordinates / 1 | U(K), then strictly increasing U(j) for every node | H + u(K) + sum(u(j)) |
| bitmap / 2 | exactly ceil(T/8) bytes | H + ceil(T/8) |
| trimmed-bitmap / 3 | U(L), then bitmap with all trailing zero bytes removed | H + u(L) + L |
| ranges / 4 | U(R), then R pairs U(start), U(length) | H + u(R) + sum(u(start)+u(length)) |
| hybrid / 5 | selected submode byte, followed by that mode's body | H + 1 + min(body lengths for modes 1..4) |

Bitmap position j is **bit j%8, least-significant-bit first**, in byte j//8.
Bits beyond T must be zero. Raw bitmap length follows from N, so no body length
is needed. Trimmed empty state is L=0; a nonempty trimmed bitmap must end with
a nonzero byte. All decoders require exact consumption; trailing bytes fail.

Ranges are maximal runs of consecutive ordinals. They must be positive-length,
ordered, disjoint and nonadjacent; adjacent runs must merge. A range can cross a
level boundary because ordinal interpretation remains unambiguous. This is a
simple deterministic run encoding of set bits, with all descriptors counted.
It also supplies the optional lightweight bitmap compression family; no general
compression dependency is introduced.

Hybrid minimizes actual candidate wire sizes **including its extra submode**;
ties select the smaller numeric submode. It may be one byte worse than the
best standalone encoding, and can be worse than PCA1. The decoder re-encodes
to reject nonminimal choices and other noncanonical representations.

## 5. Subtree/range meaning and applicability

`ranges` implements the requested subtree/range family as exact possession
ranges. A cached subtree-root hash authenticates that coordinate only: it
cannot be inverted into descendant hashes. A complete cached subtree would
mean that every represented descendant hash is locally retained and
root-authenticated. Current eviction does not preserve that property, so no
subtree-root descriptor is allowed to assert absent descendants or change
reuse semantics. This lab does not introduce derivation or subtree closure.
All schemes can express every valid current cache state, including empty
state; rows explicitly record `encoding_applicable=True`. Invalid state fails,
and no fallback silently substitutes another format.

## 6. Root/tree binding and security

Every new advertisement includes the full 32-byte root once and explicit N;
the decoder requires both to equal the externally expected fixture identity.
Coordinates are checked against that tree, including exclusion of its root.
PCA1 has implicit tree binding through the trusted root/fixture; it cannot add
N without changing Stage A. PCA2 makes the dimension check explicit. Neither
format is a new trust anchor, and root identifiers are not truncated.

Claims of possession only instruct the server which proof hashes to omit.
The client still uses its own authenticated values and verifies MTP2 to the
trusted root. Missing/corrupt cache state, wrong root, malformed framing,
invalid coordinates and noncanonical representations fail. Receiving an
advertisement never inserts hashes into the cache. As in Stage A, this is a
proof laboratory: the fixture root is pretrusted, and authority-signature,
credential/SPKI, time validity and CertificateVerify validation are not newly
implemented here. Signed-root file identity is hashed, not independently
signature-validated. Root lifecycle/revocation remain outside scope.

## 7. Matrix and deterministic pairing

Default `configs/default.json`:

```text
4 N × 3 workloads × 2 policies × 6 budgets = 144 cache trajectories
5 schemes per trajectory = 720 format configurations
1000 accesses × 720 = 720,000 observation rows
N = 16, 64, 256, 1024
workloads = uniform, zipf, clustered
policies = lru, upper-level
budgets = 0, 1, 2, 4, 8, 16 KiB (1024 bytes per CLI KB)
schemes = baseline, coordinates, bitmap, ranges, hybrid
base seed = 20260911
```

`trimmed-bitmap` is a hybrid candidate and an optional standalone scheme. To
include it as a sixth matrix factor, copy the config and add it to `schemes`:
864 configurations / 864,000 rows at 1000 accesses. No unbounded `full` cache is
included.

For N index a, workload index b, policy index p, budget index k:
`seed = base_seed + (3*a+b)*13 + 6*p+k+1`. This preserves the ordinal positions
of the Stage-A default **including a skipped full-cache slot per group**.
First bounded seed is 20260912; last is 20261066. If the comparison Stage A
used `--no-include-full-cache`, explicitly set `stage_a_included_full=false`
in a copied config (stride 12). Never silently infer a different pairing.
All schemes share that workload sequence. Each run saves the leaf lists in
`sequences.json`; audit regenerates and compares them. `--single --seed` is a
literal workload seed, matching Stage A's single-run behavior; `--full --seed`
is the base seed. The distinction matters for external pairing.

## 8. Metrics and break-even

Rows include configuration identity, seed, `access_t`, leaf, scheme, applicability,
normal/reused/transmitted hashes, exact proof and advertisement lengths,
net authentication bytes, gross and net saving, net percentage, cache occupancy,
encoding/decoding/construction/reconstruction nanoseconds and semantic-state
and partial-proof SHA-256 digests.

```text
normal_proof_bytes = 45 + 32*depth                      (MTP1)
partial_proof_bytes = 46 + ceil(depth/8) + 32*sent      (MTP2)
net_authentication_bytes = partial_proof_bytes + advertisement_bytes
net_bytes_saved = normal_proof_bytes - net_authentication_bytes
net_saving_percentage = 100 * net_bytes_saved / normal_proof_bytes
gross_proof_bytes_saved = normal_proof_bytes - partial_proof_bytes
advertisement_efficiency = gross_proof_bytes_saved / advertisement_bytes
```

Gross saving includes MTP2 framing: it is not automatically `32*reused_hashes`.
Empty state may therefore have negative gross saving. Undefined ratios are
empty CSV cells, not infinity. Advertisement efficiency >1 means positive net
saving. Per-node ratios use **pre-access** `advertised_nodes` and the current
proof's `reused_hashes`. `cached_nodes` / `cache_bytes` are **post-access**,
matching Stage A; `advertised_cache_bytes` records pre-access storage. Timings
are diagnostic Python measurements, affected by evaluation order, and cannot
establish TLS performance.

Summary reports mean/median/maximum saving, positive mean benefit and the
percentage of accesses with strictly positive saving for each configuration.
All accounting is proof-only, as in Stage A; no credential, root distribution,
TLS record, TCP/IP, certificate or handshake bytes are added.

## 9. Prerequisites and environment validation

From the repository root, Python 3.10+ (the existing Stage-A source uses modern
type annotations). Core execution and analysis use only the standard library.
Plots use the existing `campaigns/original_campaigns/pcma/requirements-plots.txt` dependency file.
Use the already existing Stage-A fixture manifest; no fixture generation is
required. These paths identify the baseline inspected during preparation:

```sh
A2=./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh
FIXTURES=artifacts/pcma/fixtures-20260911-125049/fixtures.json
STAGE_A=artifacts/results/pcma-stage-a-20260911-125123
"$A2" --help
"$A2" --check-config
test -f "$FIXTURES"
test -f "$STAGE_A/manifest.json"
```

No-argument invocation prints help and performs no experiment:

```sh
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh
```

## 10. Lightweight diagnostic

```sh
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --diagnostic
```

This runs unit tests only: N=4/8 handcrafted proof examples, coordinate-only
N=1024 round trips, negative parsers, seed/config checks and temporary
handwritten audit rows. It does not load scientific fixtures, run a 1000-access
sequence, create campaign results or make plots. Synthetic audit rows stay in
a deleted temporary directory and never become experimental evidence.

## 11. Execute one configuration

```sh
# MANUAL EXECUTION — potentially expensive
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --single \
  --fixtures artifacts/pcma/fixtures-20260911-125049/fixtures.json \
  --tree-size 1024 --workload clustered --cache-kb 1 --policy lru \
  --advertisement hybrid --seed 20260911 --accesses 1000
```

Output defaults to a unique timestamp/UUID directory. `--advertisement all`
(the default) provides all configured schemes on the same state. A single
scheme cannot establish a comparison with the other formats. Single-run
GO/NO-GO reports `INCOMPLETE_SCOPE` regardless of favorable numbers.

## 12. Execute the full matrix

Choose a new output path, retain the shell variable for later commands:

```sh
# MANUAL EXECUTION — potentially expensive
A2_RESULTS="artifacts/results/pcma-stage-a2-$(date +%Y%m%d-%H%M%S)"
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --full \
  --fixtures artifacts/pcma/fixtures-20260911-125049/fixtures.json \
  --output "$A2_RESULTS" --seed 20260911 --accesses 1000 \
  --stage-a-results artifacts/results/pcma-stage-a-20260911-125123
```

Omit `--stage-a-results` to execute independently. A full/single run automatically
audits and aggregates after simulation; it does not generate plots or launch
Stage B. Interrupted runs remain incomplete and cannot pass audit. There is no
resume/overwrite behavior: select a new directory after failure.

## 13. Audit

```sh
# MANUAL EXECUTION — potentially expensive on full CSVs
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --audit --results "$A2_RESULTS"
```

Audit checks manifest schema, expected configuration/observation counts,
full-matrix seed derivation, saved/regenerated sequences, unique complete rows,
requested formats, tree/depth and cache budgets, proof sizes, nonnegative
advertisement sizes, net equations, ratios, timings, PCA1 size formula,
identical state/proof signatures across schemes, and output hashes. It fails
with `AUDIT FAILED` on incompleteness or inconsistency. SHA-256 is an integrity
record, not a signature proving results honest; audit does not independently
replay every serialized advertisement or revalidate every fixture proof.

## 14. Aggregate and compare with Stage A

```sh
# MANUAL EXECUTION — potentially expensive on full CSVs
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --analyze \
  --results "$A2_RESULTS" --output "$A2_RESULTS/analysis-reviewed" \
  --stage-a-results artifacts/results/pcma-stage-a-20260911-125123
```

Every analysis directory must be new. `analysis/` is already produced by the
run, so use another path for later analysis. The original Stage-A CSV and
manifest are read only. External pairing requires `--stage-a-results`, verifies
its CSV hash and fixture root/signed-root identity, and matches each observation
by N/workload/policy/budget/seed/access. It checks leaves, reuse, proof sizes,
post-access cache counts and baseline advertised-node count. Mismatches abort,
rather than silently joining nonpaired data. Stage A did not store per-access
state hashes, so retrospective state equality beyond these fields cannot be
proven from its CSV. Original fixture-manifest availability is required.

Comparison CSV reports baseline/new advertisement bytes, byte and percentage
reduction, baseline/new net saving and improvement. Internal A.2 PCA1 replay is
identified separately from externally paired Stage-A comparison.

## 15. Plots

Install plotting dependencies in an environment you choose, then:

```sh
# MANUAL SETUP — optional dependency installation
python3 -m venv /tmp/pcma-a2-plots-venv
/tmp/pcma-a2-plots-venv/bin/pip install -r campaigns/original_campaigns/pcma/requirements-plots.txt
# MANUAL EXECUTION — potentially expensive, many panels
PYTHON=/tmp/pcma-a2-plots-venv/bin/python \
  ./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --plots \
  --results "$A2_RESULTS" --output "$A2_RESULTS/plots"
```

Seven plot families produce PNG/PDF: (1) mean net saving vs budget;
(2) advertisement vs budget; (3) percentage saving vs N;
(4) beneficial-authentication percentage vs budget; (5) client storage vs net
communication with Pareto frontier; (6) PCA1 vs best compact advertisement;
(7) saving vs access. Panels retain workload/policy/budget distinctions.
Pareto comparisons across budgets/policies are descriptive: Stage A used
different seeds across those configurations. Format comparisons within one
configuration are exactly paired. Figures require audited observations and
have not been generated during preparation.

## 16. Publication tables

```sh
# MANUAL EXECUTION — potentially expensive on full CSVs
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --tables \
  --results "$A2_RESULTS" --output "$A2_RESULTS/tables" \
  --stage-a-results artifacts/results/pcma-stage-a-20260911-125123
```

CSV/LaTeX tables cover all cells and the jointly best scheme/cache budget per
N/workload, ranked by mean net saving (ties prefer smaller budgets, then
lexicographically larger scheme name in this version). They include maximum,
mean, median and beneficial percentage. External advertisement reductions
require the Stage-A directory; no fake or inferred historical table is emitted.
LaTeX is a plain tabular fragment; the wide all-configurations table may need
landscape or manuscript-specific layout. No LaTeX compiler is required.

## 17. GO/NO-GO

```sh
# MANUAL EXECUTION — potentially expensive on full CSVs
./campaigns/original_campaigns/pcma_stage_a2/run_pcma_stage_a2.sh --go-no-go \
  --results "$A2_RESULTS" --output "$A2_RESULTS/decision"
```

Criteria are fixed before execution:

1. Positive mean **net** saving for N=256 and 1024 under every workload, with
   at least one bounded compact-format configuration per N/workload cell.
   Different cells may use different schemes/policies/budgets.
2. Positive benefit includes exact advertisement bytes and MTP2 framing.
3. At least one compact configuration reduces mean advertisement bytes by
   **at least 10%** relative to its paired PCA1 replay and improves mean net
   saving. This is the explicit operational definition of “materially”. The
   threshold is stored in the config/manifest and must be fixed before running.
4. Positive benefit is not exclusively clustered.
5. At least one compact encoding is evaluated; all implemented compact schemes
   omit raw cached hashes by construction.

GO requires all five and a complete primary factor scope; otherwise the report
is NO-GO (complete scope) or INCOMPLETE_SCOPE (subset/single run). Witness
configurations and individual booleans are retained. STRONG GO additionally
requires >=15% mean net saving for N=1024 under at least two workloads with
budget <=4096 bytes; witnesses may differ. This is a one-seed-per-cell
exploration, not a significance test or a claim of multi-seed robustness.
The criterion-3 comparator is internal paired PCA1; external historical pairing
is reported separately by `--analyze --stage-a-results`. No command executes
Stage B, irrespective of the decision.

## 18. Privacy

Machine-readable metadata: `configs/privacy.json`. Every format reveals the
same exact set of cached nodes. Coordinates expose individual nodes; bitmap
exposes dense possession; ranges expose exact runs, not private coarse subtree
membership. Hybrid additionally reveals a mode chosen from the occupancy
pattern. Omission of hashes does not conceal coordinates or history.

Possible leakage includes cache occupancy, locality, inferred prior leaves,
partial history, changes across snapshots and stable fingerprint-like state.
A leaf hash may have been learned as a sibling, so possession does not prove
that leaf was visited. Bounded eviction limits a snapshot but does not prevent
server tracking over time. **All compact schemes can achieve byte savings
while retaining substantial history leakage. None improves privacy here.**

## 19. Output and preservation

```text
campaigns/original_campaigns/pcma_stage_a2/             code + README + configs (new only)
artifacts/results/pcma-stage-a2-*/   manually generated, new directory only
  manifest.json                    timestamp, Git/source hashes, versions,
                                   configuration, seeds, exact fixture hashes
  observations.csv
  sequences.json
  analysis/
    summary.csv
    pareto.csv
    analysis.json                  audit + decision + output hashes
    stage_a_comparison.csv          only with explicit Stage-A results
  plots/                           separate explicit command
  tables/                          separate explicit command
  decision/                        optional standalone GO/NO-GO JSON
```

No existing Stage-A source or results are moved, renamed or overwritten.
All producers refuse an existing output directory; individual files use
exclusive creation. The runner records hashes of source Python files because
Git commit alone does not identify uncommitted preparation changes. The
fixture manifest plus every credential/proof/signed-root file is hashed when
manually running, and MTP1 proofs are verified before simulation. Analysis and
table/plot output hashes are retained in their own manifests/reports.

## 20. Known limitations and execution boundary

This is experimental Python wire serialization, not a deployable protocol.
No root-ID shortening, probabilistic filters, private set mechanism, subtree
hash expansion, signature validation addition, TLS modification, new
ClientHello extension or Stage B implementation is included. Full SHA-256
root headers can still dominate small advertisements; raw bitmaps can be
wasteful for sparse large trees; hybrid adds a byte; ranges help only suitable
occupancy patterns. Existing cache representation is deliberately not optimized.

Scientific fixtures and full analysis/plotting have not been executed during
preparation. Tiny tests validate functional plumbing, not campaign throughput,
large-output memory use, publication layout or any scientific outcome. All
substantive execution belongs to the user. See `VALIDATION.md` for the exact
lightweight validation commands executed during preparation.
