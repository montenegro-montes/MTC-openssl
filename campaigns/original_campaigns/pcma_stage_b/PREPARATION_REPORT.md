# Stage-B preparation report

Classification: **C — native PCMA TLS implementation plus the Stage-B laboratory
are present**. This class describes implemented components, not an assertion
that Codex executed or validated a TLS campaign. Offline compilation/tests pass;
the user's manually created results still require their dedicated full audit.

1. Existing Compact flow confirmed from `compact/compact.c`, `compact/patch.py`,
   `compact/scenarios.py` and measurement integration. Warm prevalidates MTR2,
   offers root in 0xffa6, receives MCB2/MTP1, verifies RPK credential/SPKI/root,
   and retains native CertificateVerify/Finished.
2. PCMA architecture: separate 0xffa7 callbacks in `native/tls.c`, native
   single-connection endpoints and sequential persistent-cache campaign runner.
3. ClientHello payload: exact PCA2/v1/ranges with full root and ULEB128 N/count/
   range descriptors; ordinary 4-byte TLS extension header counted separately.
4. Partial proof: exact Stage-A/A.2 MTP2. Server reply PCB1 frames credential and
   MTP2 lengths; it omits the unused two-byte MCB2 signed-root length.
5. Client cache: root-scoped actual hashes, LRU/upper-level, logical 69 B/node,
   private ordered PCS1 file, staged updates and post-SSL_connect atomic commit.
6. Server construction: strict ranges decode, selection from its verified MTP1
   siblings, never omission of unadvertised state.
7. Client reconstruction: strict bitmap/path/root checks followed by original
   Compact credential/SPKI/inclusion verification and native TLS authentication.
8. Added files: five native C/header files; `build.sh`, Dockerfile, Compose;
   design/runner/CLI/audit/analysis Python modules; two test modules; launcher;
   B.1 and disabled B.2 configs; README, PROTOCOL, VALIDATION and this report.
9. Existing files modified by Codex for Stage B: none. A separately appearing
   `.dockerignore` edit was neither changed nor reverted.
10. Existing Stage A/A.2, Compact cold/warm, PQ/RPK and MTC sources/results remain
    preserved. New cache writes are scoped to new Stage-B output directories.
11. Lightweight tests: native compile/link and syntax, help, Python/JSON/shell
    parsing, 4 native +5 lab tests; see VALIDATION.md for commands and corrections.
12. Codex did not execute TLS, Docker, smoke, B.1/B.2, captures or impairments.
    User-initiated diagnostic and B.1 completion markers were observed read-only.
13. Manual diagnostic: launcher `--diagnostic`; N=16 `[0,1,2,8]`, baseline, 2 KiB
    LRU, four warm and four PCMA connections, no warmup.
14. B.1: launcher `--stage-b1 --config campaigns/original_campaigns/pcma_stage_b/configs/stage-b1.json`.
15. B.2: copy the disabled selection config, choose a B.1-justified subset,
    explicitly approve the selection in the config, inspect `--stage-b2 --plan`,
    then execute manually. Nothing triggers B.2 automatically.
16. Audit: launcher `--audit --results PATH`; includes exact A.2 model/cache-file
    replay. `--check-model` provides the same complete verification.
17. Analysis: launcher `--analyze --results PATH --output NEW_PATH`; `--tables`
    and `--plots` are separate modes. Campaign-level bootstrap, not handshake
    bootstrap; outputs preserve all scenarios/metrics and paired effects.
18. B.1 default: 90 independent campaign cells, 10,800 measured +1,800 warmup =
    12,600 handshakes. PQ and warm are each executed once per logical access.
    Diagnostic: one cell/eight handshakes. B.2 count depends on manual selection.
19. Security limits: trusted local single-writer cache directory, no rollback/
    revocation/root lifecycle management, no fallback. Loaded hashes must still
    verify to the signed root. Client completion does not imply server app ACK.
20. Privacy limits: explicit operator mapping gates advertising, but ClientHello
    precedes endpoint authentication. History inference, fingerprinting,
    probing, linkability and cross-service correlation remain unresolved.
21. A.2 differences: ranges and MTP2 bytes/cache order match offline tests;
    actual warm-relative plaintext TLS saving is A.2 net saving +36 B. Native
    PCMA defensively repeats Merkle verification for staged learning. Setup and
    disk commit are outside the handshake window; timers have documented overlap.
22. Remaining validation limits: no Codex end-to-end TLS/capture/performance run;
    no full scientific audit/analysis or publication-layout validation. The
    user's completed-looking runs are not promoted to findings without audit.

The README contains copyable commands with every TLS launch explicitly marked
for manual execution. Implementation is frozen at the source identities already
recorded by the user's runs; only this report and VALIDATION.md were added after
the read-only source comparison. Do not mix protocol/timing changes into those
results without a new version and campaign.
