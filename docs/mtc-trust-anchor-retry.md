# Minimal trust-anchor retry

This is an opt-in protocol-validation tool. Existing `s_client`/`s_server`,
MTC fixtures, campaign wrappers and `handshake_wall_ms` are unchanged.
It does not implement temporal landmark evolution or performance measurements.

## Protocol scope

The active references are MTC -07 and [Trust Anchor IDs -06](https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-06.txt).
TAI -06 Sections 5.1 and 5.6 define the available-ID list in
EncryptedExtensions and recovery on a new connection. A client SHOULD retry at
most once per connection attempt. This is connection retry, not TLS
HelloRetryRequest.

The active codepoint is provisional `0xca34`, aligned with Chromium/BoringSSL,
not a final IANA assignment. Historical runs used private `0xffa7` and remain
unchanged. This isolated retry peer has one candidate credential. Its controller
requests one ID per connection, while the native parser accepts multiple
requested IDs and multiple available IDs. Binary IDs are limited to 32 bytes
(TAI -06 Section 4). The TLS parsers accept canonically encoded IDs with
components larger than UINT64_MAX and discard them as locally unsupported;
the text configuration and local MTC codec still limit each component to
UINT64_MAX (TAI -06 Section 8). The Python retry controller also validates
canonical wire IDs before decoding; it ignores locally unsupported large
components while retaining later supported IDs in server preference order.
The 22 deterministic controller tests and the updated native C parser test
passed offline on 31 October 2026 using the repository mounted read-only in
the local MTC image. The image's embedded `MTC_SHA256` does not cover this
Python controller or the mounted test sources.
An empty requested list is valid discovery; an empty available list is invalid.
The controller rejects duplicate available IDs. MCA2/MTB2 remain local
out-of-band storage. No complete draft conformance or interoperability claim
is made.

The retry server receives trust, credential and private-key paths, **no independent
advertised ID**. It validates the checkpoint, MTC proof, server leaf purpose,
validity and credential/private-key correspondence before advertising the ID
derived from that validated mapping. An incompatible request is allowed to
reach EncryptedExtensions with the candidate ID; the fallback CertificateEntry
has no selection confirmation. The client aborts at incompatible EE with
`unknown_ca`, records `trust_anchor_mismatch` separately and exits. Malformed
input instead generates `decode_error` and cannot enable retry.

`--initial-id` is an explicit controlled advertisement override for this minimal
experiment: the preflight deliberately announces synthetic incompatible A while
the configured cryptographic trust state permits B. It does not model two installed
trust stores or install a trust anchor for A. Only B may ultimately authenticate;
support for a general multi-anchor client trust inventory is outside this subset.

Available IDs are unauthenticated discovery input until TLS authentication
completes. They never install trust. The controller validates canonical encoding,
requires the selected ID to have actually appeared, and permits only the ID
derived by native inspection of the operator's authenticated local trust state.
That public trust file is copied once to a private temporary directory for all
attempts. No server-supplied keys or landmarks are accepted.

Each native client subprocess owns one socket, SSL context and SSL object.
`subprocess.run` returns only after process termination; timeout kills and waits.
The first SSL object/socket are freed/closed before a second process starts.
Session caching and tickets are disabled. `SSL_VERIFY_PEER`, the unchanged MTC
verifier, leaf/hostname constraints and native CertificateVerify/Finished remain
active. No application bytes are exchanged by this validation peer.

## Commands

The MTC image builds `/opt/mtc/retry-peer` from `retry_peer.c`. For a local build
use headers/libraries from the same OpenSSL installation:

```sh
cc -Wall -Wextra -Werror -Wno-unused-parameter \
  -I/opt/openssl-profile/include src/mtc/retry_peer.c \
  -L/opt/openssl-mtc/lib -Wl,-rpath,/opt/openssl-mtc/lib \
  -lssl -lcrypto -o /tmp/mtc-retry-peer
```

Parser/controller unit tests and native offline credential/parser tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s src/mtc -p test_retry.py
cc -Wall -Wextra -Werror -Wno-unused-parameter \
  -I/opt/openssl-profile/include src/mtc/test_retry_native.c \
  -L/opt/openssl-mtc/lib -Wl,-rpath,/opt/openssl-mtc/lib \
  -lssl -lcrypto -o /tmp/mtc-test-retry-native
/tmp/mtc-test-retry-native TRUST CERT KEY
```

The native offline test expects the controlled ECDSA-P256 fixture ID
`32473.101.1.1.1`; it neither generates nor edits fixtures.

Explicit small preflight: exactly one transaction and two loopback connections,
with readiness signaled over stdout (no readiness TCP probe):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 src/mtc/preflight_retry.py \
  --peer /opt/mtc/retry-peer --trust TRUST --cert CERT --key KEY \
  --hostname CERT_HOSTNAME --initial-id 32473.9.1.1.1
```

Use a different incompatible initial ID when needed. All fixture paths are
read-only. The preflight prints structured results, not timing measurements.

Manual direct controller invocation against a running retry peer:

```sh
python3 src/mtc/retry.py --host 127.0.0.1 --port 19443 \
  --hostname CERT_HOSTNAME --trust TRUST --initial-id INITIAL_ID
```

`--output NEW.json` creates an exclusive file; an existing file is rejected
before making connections. The server peer accepts a configured maximum of one
or two connections and closes after a bounded wait. Client/controller timeouts
bound failed attempts; no third attempt is possible.

## Evidence and limits

Reports contain transaction ID, requested ID, supported and selected IDs,
attempt/retry counts, per-attempt/final outcomes, and connection IDs based on
native ClientHello randoms. Both endpoints report the same connection ID. They
also report TLS version, cipher, group NID and session reuse. The selected
landmark is the validated configured individual landmark.

Cases A–E are controller/parser unit tests. Native offline tests additionally
exercise mismatch/discovery, exact-ID selection, malformed lists and credential
binding. These test outcomes are not substitutes for live TLS evidence.
The dedicated ECDSA preflight has demonstrated both one bounded retry and a
direct authenticated connection against real loopback sockets. These single-
candidate transactions do not demonstrate a multi-ID EncryptedExtensions list
on the wire. Cases C–E use injected controller results rather than hostile live
servers. The original baseline TLS suite and PQ retry are not covered by the
small ECDSA preflight.

No timing/byte framework is added. Each attempt remains separately owned; a
future external metric may include connection setup and transition overhead
without redefining existing single-handshake measurements. This isolated peer
does not emit existing performance telemetry.

## Landmark ID distinction

`.1.<log>.<landmark>` identifies an individual; `.2.<log>.<landmark>` identifies
an initial negotiation group. Ordinary landmark ClientHello advertises the group;
EE/credential binding and an explicit retry keep the individual from authenticated
configuration. `retry.py` classifies canonical individual suffixes structurally,
including multi-byte component values, rather than testing `.1.1.1`. This only
changes report classification, not the exact locally trusted retry-target check.
A `.2` group is never classified as an individual landmark. The native configuration
loader remains restricted to log 1 / landmark 1. The current offline tests
exercise group/ID parsing; all earlier retry evidence retains its original IDs
and meaning.
