"""Exact leaf-zero initial-landmark serialization, without constructing a tree."""
from size_analysis import certificate, certificate_parts, cover, proof, tls_certificate_message_size
from core import H

HASH_BYTES = len(H(b''))
# Largest complete population expressible with an exclusive uint48 endpoint.
MAXIMUM_SUPPORTED_N = (1 << 48) - 1
IMPLEMENTATION_LIMIT = 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def read_vector(raw, pos, width=2):
    require(pos+width <= len(raw), 'truncated vector length')
    n = int.from_bytes(raw[pos:pos+width], 'big'); pos += width
    require(pos+n <= len(raw), 'truncated vector')
    return raw[pos:pos+n], pos+n


def decode_proof(raw):
    extensions, pos = read_vector(raw, 0)
    require(pos+12 <= len(raw), 'truncated endpoints')
    start = int.from_bytes(raw[pos:pos+6], 'big')
    end = int.from_bytes(raw[pos+6:pos+12], 'big')
    hashes, pos = read_vector(raw, pos+12)
    signatures, pos = read_vector(raw, pos)
    require(pos == len(raw) and len(hashes) % HASH_BYTES == 0, 'invalid proof framing')
    return extensions, start, end, hashes, signatures


def proof_hash_count(n):
    require(isinstance(n,int) and 1 <= n <= MAXIMUM_SUPPORTED_N, 'population outside representable full-landmark range')
    return max(0, (n-1).bit_length()-1)


def intervals():
    for k in range(48):
        yield (1 if k == 0 else (1 << k)+1), min(1 << (k+1), MAXIMUM_SUPPORTED_N), k


def model(tbs, n):
    start, end = cover(0,n)[0]
    count = proof_hash_count(n)
    require(count == (end-start-1).bit_length(), 'cover/hash-count disagreement')
    encoded = proof(start,end,[bytes(HASH_BYTES)]*count)
    der = certificate(tbs,encoded)
    return dict(tree_size=n,subtree_start=start,subtree_end=end,proof_hashes=count,
                proof_hash_bytes=HASH_BYTES*count,encoded_proof_bytes=len(encoded),
                mtc_der_bytes=len(der),tls_certificate_message_bytes=tls_certificate_message_size([der],mtc_confirmation=True))


def audit(raw,n=16):
    outer,t = certificate_parts(raw)
    require(outer[2][1][0] == 0, 'BIT STRING unused bits')
    ex,start,end,hashes,sigs = decode_proof(outer[2][1][1:])
    require(ex == b'' and sigs == b'', 'landmark proof extensions/signatures unexpectedly nonempty')
    require((start,end) == cover(0,n)[0], 'wrong leaf-zero initial-landmark subtree')
    require(int.from_bytes(t[1][1],'big') == 1 << 48, 'anchor must be log 1 leaf 0')
    require(len(hashes) == HASH_BYTES*proof_hash_count(n), 'fixture proof count mismatch')
    reconstructed = certificate(outer[0][2],proof(start,end,[hashes[i:i+HASH_BYTES] for i in range(0,len(hashes),HASH_BYTES)]))
    require(reconstructed == raw, 'fixture does not round-trip byte-for-byte')
    predicted = model(outer[0][2],n)
    require(predicted['mtc_der_bytes'] == len(raw), 'model differs from fixture')
    spki = len(t[6][2]);fixed = 2+6+6+2+2
    other = len(raw)-len(outer[0][2])-fixed-len(hashes)
    result = dict(certificate_base_bytes=len(outer[0][2])-spki,spki_bytes=spki,
                  proof_fixed_bytes=fixed,number_of_proof_hashes=len(hashes)//HASH_BYTES,
                  proof_hash_bytes=len(hashes),signatures_bytes=len(sigs),other_bytes=other,
                  total_MTC_DER_bytes=len(raw),TLS_Certificate_message_bytes=len(raw)+17,
                  tls_framing_bytes=17,confirmation_extension_bytes=4,merkle_root_bytes=0,
                  landmark_trust_material_bytes=0,fixture_roundtrip=True,model_matches_fixture=True)
    require(sum(result[k] for k in ('certificate_base_bytes','spki_bytes','proof_fixed_bytes','proof_hash_bytes','signatures_bytes','other_bytes')) == len(raw),'breakdown sum mismatch')
    return outer[0][2],result


def crossover(tbs,target,maximum=MAXIMUM_SUPPORTED_N):
    require(1 <= maximum <= MAXIMUM_SUPPORTED_N, 'invalid maximum')
    for first,last,k in intervals():
        if first > maximum:
            break
        row = model(tbs,first)
        if row['tls_certificate_message_bytes'] >= target:
            previous = model(tbs,first-1) if first > 1 else None
            return dict(last_better_N=first-1 if previous else '',
                        last_better_mtc_bytes=previous['tls_certificate_message_bytes'] if previous else '',
                        crossover_N=first,crossover_mtc_bytes=row['tls_certificate_message_bytes'],
                        proof_hashes_at_crossover=k,difference_bytes=row['tls_certificate_message_bytes']-target,
                        mathematical_threshold_N=first,first_power_of_two_N=(1 << (first-1).bit_length()) if (1 << (first-1).bit_length()) <= maximum else '',
                        status='CROSSED')
    row = model(tbs,maximum)
    return dict(last_better_N=maximum,last_better_mtc_bytes=row['tls_certificate_message_bytes'],
                crossover_N='',crossover_mtc_bytes='',proof_hashes_at_crossover='',
                difference_bytes=row['tls_certificate_message_bytes']-target,mathematical_threshold_N='',first_power_of_two_N='',
                status='NO_CROSSOVER_WITHIN_PROTOCOL_RANGE')
