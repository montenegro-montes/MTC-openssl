from core import *
import core

def rejected(call,label):
    try:call()
    except ValueError:return
    raise AssertionError('accepted '+label)

# A deterministic v3 TBSCertificate with all three optional fields.  The [3]
# field is an exact X.509 Extensions DER value, distinct from MTC extensions.
x509_extensions=der(0xa3,seq(seq(oid('2.5.29.19'),der(4,b'\x30\x00'))))
tbs=seq(der(0xa0,integer(2)),integer(7),ALG,name('32473.101'),
        seq(der(23,b'250101000000Z'),der(23,b'260101000000Z')),
        seq(),seq(ALG,der(3,b'\0public-key')),der(0x81,b'\0issuer'),
        der(0x82,b'\0subject'),x509_extensions)

tbs_log=TBSCertificateLogEntry.from_tbs_certificate(tbs)
assert tbs_log.extensions==x509_extensions
assert TBSCertificateLogEntry.decode(tbs_log.encode())==tbs_log
assert content(tbs_log.der(),0x30)==tbs_log.encode()

structured=[(0x1234,b'alpha'),(2,b''),(0xffff,b'omega')]
canonical=encode_mtc_extensions(structured)
assert canonical==(b'\x00\x02\x00\x00'+b'\x12\x34\x00\x05alpha'+
                   b'\xff\xff\x00\x05omega')
assert parse_mtc_extensions(canonical)==((2,b''),(0x1234,b'alpha'),(0xffff,b'omega'))
assert encode_mtc_extensions(canonical)==canonical

encoded=entry(tbs,canonical)
decoded=MTCLogEntry.decode(encoded)
assert decoded.extensions==canonical
assert decoded.entry_type==TBS_CERT_ENTRY
assert decoded.tbs_certificate_log_entry()==tbs_log
assert decoded.encode()==encoded

# MTCProof reuses, byte for byte, the canonical MTC extension contents.
p=proof(0,1,[],(),decoded.extensions)
assert proof_extensions(p)==entry_extensions(encoded)==canonical
assert proof(0,1,[],(),entry_extensions(encoded))==p
assert entry(tbs)[:2]==proof(0,1,[])[:2]==b'\0\0'

# Unknown well-formed extension types are retained opaquely.
unknown=b'\xfe\xdc\x00\x03\x00\xff\x01'
assert encode_mtc_extensions(unknown)==unknown
assert entry_extensions(entry(tbs,unknown))==unknown

# The structured encoder canonicalizes order, but never duplicate types.
assert encode_mtc_extensions([(9,b'b'),(1,b'a')])==b'\0\1\0\1a\0\x09\0\1b'
rejected(lambda:encode_mtc_extensions([(1,b'a'),(1,b'b')]),'structured duplicate')

malformed_extensions=[
    b'\x12\x34',                         # old incomplete vector
    b'\x00\x01\x00',                   # truncated length
    b'\x00\x01\x00\x02x',             # truncated value
    b'\x00\x02\x00\x00\x00\x01\x00\x00', # reordered
    b'\x00\x01\x00\x00\x00\x01\x00\x00', # duplicate
]
for value in malformed_extensions:
    rejected(lambda value=value:encode_mtc_extensions(value),'malformed extension vector')
    rejected(lambda value=value:proof(0,1,[],(),value),'malformed proof extensions')

rejected(lambda:MTCLogEntry.decode(b'\0\x05\0\1'), 'overlong extensions length')
rejected(lambda:MTCLogEntry.decode(b'\0\0\0'), 'truncated entry type')
rejected(lambda:MTCLogEntry.decode(b'x'*65536), 'oversized entry')
rejected(lambda:proof_extensions(p+b'\0'), 'trailing MTCProof data')
rejected(lambda:proof_extensions(b'\0\x04\x12\x34\0\0'+p[2:]),
         'malformed MTCProof extensions')

# null_entry exists only as a log entry, has valid MTC extensions and no payload.
null=null_entry(canonical)
parsed_null=MTCLogEntry.decode(null)
assert parsed_null.entry_type==NULL_ENTRY and parsed_null.entry_data==b''
assert parsed_null.extensions==canonical and parsed_null.encode()==null
rejected(lambda:MTCLogEntry.decode(null+b'payload'),'null_entry payload')
rejected(parsed_null.tbs_certificate_log_entry,'null_entry as tbs_cert_entry')

# tbs_cert_entry consumes the entire remainder; extra or non-DER data fails.
rejected(lambda:MTCLogEntry.decode(encoded+b'\0'),'trailing tbs_cert_entry data')
noncanonical=tbs_log.encode().replace(b'\x30\x00',b'\x30\x81\x00',1)
rejected(lambda:MTCLogEntry(canonical,TBS_CERT_ENTRY,noncanonical).encode(),
         'noncanonical TBSCertificateLogEntry DER')

# A proof using different canonical extensions hashes a different leaf.
different=encode_mtc_extensions([(2,b'different')])
assert H(b'\0'+entry(tbs,canonical))!=H(b'\0'+entry(tbs,different))
assert proof_extensions(proof(0,1,[],(),different))!=entry_extensions(encoded)

print('MTCLogEntry/TBSCertificateLogEntry canonical codec tests PASS')
