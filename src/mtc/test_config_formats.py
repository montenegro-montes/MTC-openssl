"""Focused deterministic tests for MCA2, MCP2, and MTB2 codecs."""

from dataclasses import replace

from config_formats import (
    MAX_UINT48,
    MCA2Authority,
    MCP2Checkpoint,
    MTB2Bundle,
    decode_mca2,
    decode_mcp2,
    decode_mtb2,
    encode_mca2,
    encode_mcp2,
    encode_mtb2,
)
from core import (H, cover, decode_subtree_signature_block,
                  encode_subtree_signature_block, uint)


def rejected(function, *args):
    try:
        function(*args)
    except ValueError:
        return
    raise AssertionError("invalid value accepted")


def spki(payload=b"opaque-spki"):
    """Structurally framed opaque bytes; key parsing belongs to consumers."""
    return payload


def authority(log_number=1, signers=None):
    if signers is None:
        signers=(("32473.1", spki()), ("32473.2", spki(b"other-spki")))
    first=log_number << 48
    return MCA2Authority("32473.1", tuple(signers), log_number,
                         first, first + 1023)


def checkpoint(size=1, signatures_value=None):
    if signatures_value is None:
        signatures_value=(("32473.1", b"ca"), ("32473.2", b"cosigner"))
    intervals=cover(0, size)
    left_hash=H(b"left:" + uint(size, 6))
    right_hash=H(b"") if size == 1 else H(b"right:" + uint(size, 6))
    root_hash=left_hash if size == 1 else H(b"\x01" + left_hash + right_hash)
    return MCP2Checkpoint(
        size, 123, root_hash, tuple(signatures_value),
        ((intervals[0][0], intervals[0][1], left_hash),
         (intervals[1][0], intervals[1][1], right_hash)),
    )


def test_mca2():
    value=authority()
    encoded=encode_mca2(value)
    assert decode_mca2(encoded)==value
    assert encoded.startswith(b"MCA2\x07" + b"32473.1" + b"\x00\x02")
    assert encoded[-18:]==b"\x00\x01" + uint(1 << 48, 8) + uint((1 << 48) + 1023, 8)

    high=authority(65535)
    assert decode_mca2(encode_mca2(high))==high
    rejected(encode_mca2, authority(0))

    three=authority(signers=(("32473.1",spki()),("32473.2",spki()),
                             ("32473.3",spki())))
    assert len(decode_mca2(encode_mca2(three)).signers)==3

    large_spki=spki(b"s" * 65536)
    large=authority(signers=(("32473.1",large_spki),))
    large_encoded=encode_mca2(large)
    assert len(decode_mca2(large_encoded).signers[0][1])>0xffff

    for damaged in (b"BAD2"+encoded[4:],encoded[:-1],encoded+b"\x00",
                    encoded[:5]+b"\xff"+encoded[6:]):
        rejected(decode_mca2,damaged)


def test_mcp2():
    for size in (1,1024,1025,MAX_UINT48):
        value=checkpoint(size)
        encoded=encode_mcp2(value)
        assert decode_mcp2(encoded)==value
        assert encoded[:4]==b"MCP2"
        assert encoded[4:10]==uint(size,6)
        # No count byte: exactly two fixed 44-byte covering records end MCP2.
        signature_length=int.from_bytes(encoded[50:53],"big")
        assert len(encoded)==53+signature_length+88

    rejected(encode_mcp2,checkpoint(0))
    valid=encode_mcp2(checkpoint(1025))
    rejected(decode_mcp2,valid[:-1])
    rejected(decode_mcp2,valid+b"\x00")

    bad_intervals=replace(checkpoint(1025),subtrees=(
        (0,1,checkpoint(1025).subtrees[0][2]),checkpoint(1025).subtrees[1]))
    rejected(encode_mcp2,bad_intervals)
    bad_hash=replace(checkpoint(2),root_hash=b"\x00"*32)
    rejected(encode_mcp2,bad_hash)

    # The aggregate crosses uint16 exactly and is encoded canonically as uint24.
    wide=checkpoint(1,(("1",b"a"*65528),("2",b"")))
    wide_encoded=encode_mcp2(wide)
    assert wide_encoded[50:53]==b"\x01\x00\x00"
    assert decode_mcp2(wide_encoded)==wide

    signature_offset=53
    noncanonical=bytearray(encode_mcp2(checkpoint(1)))
    noncanonical[signature_offset]=2
    noncanonical[signature_offset+1:signature_offset+3]=b"\x80\x01"
    rejected(decode_mcp2,bytes(noncanonical))

    first=encode_subtree_signature_block((("1",b"a"),))
    second=encode_subtree_signature_block((("2",b"b"),))
    rejected(decode_subtree_signature_block,first+first)
    rejected(decode_subtree_signature_block,second+first)


def test_mtb2():
    base=MTB2Bundle(authority(),checkpoint(1025))
    encoded=encode_mtb2(base)
    assert decode_mtb2(encoded)==base
    assert encoded.startswith(b"MTB2"+uint(len(encode_mca2(base.authority)),4)+b"MCA2")
    assert encoded.endswith(b"\x00")

    for landmark in (1,1<<32,MAX_UINT48):
        value=replace(base,signaling_landmark=landmark)
        encoded=encode_mtb2(value)
        assert decode_mtb2(encoded)==value
        assert encoded.endswith(b"\x01"+uint(landmark,6))

    rejected(encode_mtb2,replace(base,signaling_landmark=0))
    valid=encode_mtb2(base)
    rejected(decode_mtb2,valid[:-1]+b"\x02")
    rejected(decode_mtb2,valid+b"\x00")

    authority_length=int.from_bytes(valid[4:8],"big")
    checkpoint_length_offset=8+authority_length
    checkpoint_offset=checkpoint_length_offset+4
    bad_authority=bytearray(valid);bad_authority[8:12]=b"BAD2"
    rejected(decode_mtb2,bytes(bad_authority))
    bad_checkpoint=bytearray(valid);bad_checkpoint[checkpoint_offset:checkpoint_offset+4]=b"BAD2"
    rejected(decode_mtb2,bytes(bad_checkpoint))


def main():
    test_mca2()
    test_mcp2()
    test_mtb2()
    print("MCA2/MCP2/MTB2 codec tests PASS")


if __name__=="__main__":
    main()
