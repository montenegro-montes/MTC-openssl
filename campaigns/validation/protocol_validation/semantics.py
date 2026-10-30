"""Parsing/classification for the active MTC-07 and trust-anchor-ids-06 subset."""
DRAFT = 'draft-ietf-tls-trust-anchor-ids-06'
# Read the authoritative C constant; no alternate wire codepoint or fallback.
from pathlib import Path
import re
_HEADER = Path(__file__).resolve().parents[3] / 'src/mtc/mtc.h'
_MATCH = re.search(r'^#define MTC_EXT (0x[0-9a-fA-F]+)$', _HEADER.read_text(), re.M)
if _MATCH is None:
    raise ValueError('Missing MTC_EXT in ' + str(_HEADER))
MTC_EXT = int(_MATCH.group(1), 16)
CODEPOINT = f'0x{MTC_EXT:04x}'
CODEPOINT_STATUS = 'provisional/Chromium-BoringSSL-aligned'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def decode_id(data):
    require(1 <= len(data) <= 32, 'TrustAnchorID length outside 1..32')
    parts = []
    value = 0
    first = True
    for byte in data:
        require(not (first and byte == 0x80), 'nonminimal relative OID component')
        value = (value << 7) | (byte & 127)
        first = not (byte & 128)
        if first:
            parts.append(value)
            value = 0
    require(first, 'unfinished relative OID component')
    return tuple(parts)


def encode_id(parts):
    out = bytearray()
    for value in parts:
        require(isinstance(value, int) and value >= 0, 'invalid relative OID component')
        chunk = [value & 127]
        value >>= 7
        while value:
            chunk.insert(0, (value & 127) | 128)
            value >>= 7
        out.extend(chunk)
    decode_id(out)
    return bytes(out)


def decode_list(data, *, available=False):
    require(len(data) >= 2, 'missing trust anchor list length')
    require(int.from_bytes(data[:2], 'big') == len(data)-2, 'trust anchor list length mismatch')
    ids = []
    pos = 2
    while pos < len(data):
        size = data[pos]
        pos += 1
        require(size > 0 and pos+size <= len(data), 'empty/truncated TrustAnchorID')
        ids.append(decode_id(data[pos:pos+size]))
        pos += size
    require(not available or bool(ids), 'AvailableTrustAnchorList must not be empty')
    # Requested order is unspecified; Available order is preference order, not OID sorting.
    return ids


def encode_list(ids):
    body = b''.join(bytes([len(x)]) + x for x in map(encode_id, ids))
    require(len(body) <= 65535, 'list too long')
    return len(body).to_bytes(2, 'big') + body


def trust_mapping(ch, ee, certificate_extensions, ca_id, mode, log, landmark,
                  multi_candidate=False):
    """Classify observed payloads for one candidate or the two-credential server."""
    result = dict(draft_revision=DRAFT, extension_codepoint=CODEPOINT,
                  codepoint_status=CODEPOINT_STATUS, draft_extension_type='TBD',
                  wire_structure_match=False, message_semantics_match=False,
                  scope=('two candidates, initial single-log group or exact individual-ID negotiation'
                         if multi_candidate else
                         'single candidate, initial single-log group or exact individual-ID negotiation; not complete trust_anchors support'))
    try:
        requested = decode_list(ch)
        available = decode_list(ee, available=True)
        require(len(certificate_extensions) == 1, 'expected one CertificateEntry in MTC subset')
        marker = certificate_extensions[0]
        require(marker is not None and marker['length'] == 0 and marker['data'] == b'',
                'first CertificateEntry must contain the empty confirmation extension')
        result['wire_structure_match'] = True
        ca = tuple(int(x) for x in ca_id.split('.'))
        require(log > 0 and landmark > 0, 'invalid configured log/landmark')
        individual = ca + (1, log, landmark)
        group = ca + (2, log, landmark)
        expected = individual if mode == 'landmark' else ca
        require(mode in ('landmark', 'standalone'), 'unknown MTC mode')
        result.update(requested_ids=['.'.join(map(str, x)) for x in requested],
                      available_ids=['.'.join(map(str, x)) for x in available],
                      ca_id=ca_id, log_number=log, landmark_number=landmark,
                      individual_landmark_id='.'.join(map(str, individual)),
                      landmark_group_id='.'.join(map(str, group)),
                      landmark_group_advertised=group in requested,
                      requested_order='unordered',
                      available_order=('Landmark then Standalone' if multi_candidate else
                                       'single candidate; preference order trivial'))
        group_selected = mode == 'landmark' and requested == [group]
        expected_available = [individual, ca] if multi_candidate else [expected]
        membership = group_selected and log == 1 and landmark == 1 and available == expected_available
        result['group_membership_valid'] = membership if group_selected else None
        require((requested == [expected] or membership) and available == expected_available,
                'observed IDs do not match the configured individual anchors')
        result.update(status='PASS_EXPERIMENTAL_CODEPOINT', message_semantics_match=True,
                      reason='Observed configured available-ID order and group-member or exact-ID selection; codepoint is provisional, not a final IANA assignment.')
        result['landmark_group_recommendation'] = dict(
            status=('PASS' if membership else 'UNRESOLVED') if mode == 'landmark' else 'NOT_APPLICABLE',
            section='MTC-07 8.2.1',
            reason=('Initial single-log group advertised and its individual landmark selected.' if membership else 'No landmark group negotiation observed; exact individual selection remains supported. General groups and automatic retry are not implemented.'))
    except (ValueError, TypeError, KeyError) as error:
        result.update(status='FAIL', reason=str(error))
    return result


def timestamp_checks(mode, checkpoint):
    """Called only after object signatures were verified. No current-clock claim."""
    proof = dict(status='PASS' if mode == 'standalone' else 'NOT_APPLICABLE',
                 section='MTC-07 6.2 / 7.2', signed_timestamp=0,
                 reason='MTCProof cosignatures verified with uint64 zero; landmark proof has no cosignatures.')
    checkpoint_check = dict(status='NOT_APPLICABLE', section='MTC-07 5.3.1 / 5.3.2')
    if checkpoint is not None:
        value = checkpoint[0]
        require(0 < value < 1 << 64, 'invalid uint64 checkpoint timestamp')
        checkpoint_check.update(status='PASS', timestamp_encoding='uint64 seconds since POSIX Epoch',
                                timestamp=value, signed_start=0,
                                scope='encoding and authenticated checkpoint range only',
                                signer_assertions=dict(status='UNRESOLVED',
                                    reason='Signature authenticates the assertion, not the actual signing time or largest tree independently observed by the cosigner.'))
    return dict(mtcproof=proof, checkpoint=checkpoint_check,
                local_policy=dict(status='LOCAL_POLICY', source='src/mtc/mtc.c:mtc_load',
                    rule='checkpoint timestamp > 0 and <= current time; no maximum-age window',
                    execution_status='NOT_EXECUTED',
                    reason='Source-inspected native policy; offline object validation does not evaluate the current clock.'))
