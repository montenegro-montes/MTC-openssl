"""Focused prepare() issuance-log-number regression tests."""

import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import core
from cosigner import ExternalCosigner
from config_formats import decode_mca2, decode_mtb2
import prepare


def certificate_serial(path):
    _,fields=core.certificate_parts(path.read_bytes())
    return int.from_bytes(fields[1][1],"big")


def proof_signatures(encoded):
    offset=2+int.from_bytes(encoded[:2],"big")+12
    offset+=2+int.from_bytes(encoded[offset:offset+2],"big")
    block_length=int.from_bytes(encoded[offset:offset+3],"big");offset+=3
    block=encoded[offset:offset+block_length];result=[];position=0
    while position<len(block):
        length=block[position];position+=1
        identity=block[position:position+length];position+=length
        length=int.from_bytes(block[position:position+2],"big");position+=2
        signature=block[position:position+length];position+=length
        result.append((identity,signature))
    return result


with tempfile.TemporaryDirectory(prefix="mtc-prepare-log-number-") as temporary:
    temporary=Path(temporary)
    profile=prepare.crypto_profile("ecdsa-p256")
    original_tbs=core.seq(
        core.der(0xa0,core.integer(2)),core.integer(7),core.ALG,
        core.name(profile["ca_id"]),
        core.seq(core.der(23,b"250101000000Z"),
                 core.der(23,b"490101000000Z")),
        core.seq(),core.seq(core.ALG,core.der(3,b"\0public-key")))
    original=temporary/"original.pem"
    original.write_bytes(core.pem(core.certificate(original_tbs,b"original")))
    signer_keys=[temporary/f"signer-{index}.key" for index in range(2)]
    for index,key in enumerate(signer_keys):key.write_bytes(b"key-"+bytes([index]))

    signed_messages=[]
    def fake_sign(key,data,family):
        signed_messages.append(data)
        return core.H(Path(key).read_bytes()+data)

    def fake_command(*args,data=None):
        assert args[0]=="pkey" and "-pubout" in args
        key=Path(args[args.index("-in")+1])
        return b"public-"+key.read_bytes()

    clock=iter([100.0]*100)
    common=dict(originals=[original],signer_keys=signer_keys)
    with patch.object(prepare,"sign",side_effect=fake_sign), \
         patch.object(prepare,"command",side_effect=fake_command), \
         patch.object(prepare.time,"time",return_value=1_800_000_000), \
         patch.object(prepare.time,"perf_counter",side_effect=lambda:next(clock)):
        default_out=temporary/"default-log-1"
        explicit_out=temporary/"explicit-log-1"
        prepare.prepare(default_out,temporary,"ecdsa-p256",1,**common)
        prepare.prepare(
            explicit_out,temporary,"ecdsa-p256",1,log_number=1,**common)

        signaling_outputs={}
        for value in (None,2,1<<32,(1<<48)-1):
            output=temporary/("signaling-"+str(value))
            prepare.prepare(
                output,temporary,"ecdsa-p256",1,
                signaling_landmark=value,**common)
            signaling_outputs[value]=output

        assert sorted(p.relative_to(default_out) for p in default_out.rglob("*"))==sorted(
            p.relative_to(explicit_out) for p in explicit_out.rglob("*"))
        for path in default_out.rglob("*"):
            if path.is_file():
                relative=path.relative_to(default_out)
                assert path.read_bytes()==(explicit_out/relative).read_bytes()

        log_2_out=temporary/"log-2"
        encoded_tbs=core.mtc_tbs(
            core.from_pem(original.read_bytes()),profile["ca_id"],0,2)
        entries=[core.entry(encoded_tbs)]
        external=ExternalCosigner(
            profile["cosigner_ids"][1],signer_keys[1],profile["ca_id"],
            "ecdsa-p256",log=2,state_path=temporary/"log-2-state.json")
        before_log_2=len(signed_messages)
        meta=prepare.prepare(
            log_2_out,temporary,"ecdsa-p256",1,log_number=2,
            external_cosigner=external,
            external_consistency_proof=core.consistency(entries,0),**common)

    assert certificate_serial(log_2_out/"standalone-0000.der")==2<<48
    assert certificate_serial(log_2_out/"landmark-0000.der")==2<<48
    authority=decode_mca2((log_2_out/"authority.bin").read_bytes())
    assert (authority.ca_id,authority.log_number,authority.min_serial,
            authority.max_serial)==(profile["ca_id"],2,2<<48,2<<48)
    assert (log_2_out/"authority.bin").read_bytes().startswith(b"MCA2")
    trust=(log_2_out/"trust.bin").read_bytes()
    bundle=decode_mtb2(trust)
    assert trust.startswith(b"MTB2")
    assert (authority.signers,authority.log_number,authority.min_serial,
            authority.max_serial)==(
                bundle.authority.signers,bundle.authority.log_number,
                bundle.authority.min_serial,bundle.authority.max_serial)
    assert bundle.checkpoint.tree_size==1
    assert bundle.signaling_landmark==1
    assert decode_mtb2(
        (default_out/"trust.bin").read_bytes()).signaling_landmark==1
    for value,output in signaling_outputs.items():
        assert (output/"authority.bin").read_bytes().startswith(b"MCA2")
        generated=(output/"trust.bin").read_bytes()
        assert generated.startswith(b"MTB2")
        assert decode_mtb2(generated).signaling_landmark==value
    assert meta["log_number"]==2
    assert json.loads((log_2_out/"manifest.json").read_text())["log_number"]==2
    assert external.accepted.tree_size==1

    log_2_messages=signed_messages[before_log_2:]
    assert log_2_messages
    assert all(b"oid/1.3.6.1.4.1."+profile["ca_id"].encode()+b".0.2" in value
               for value in log_2_messages)
    assert all(b"oid/1.3.6.1.4.1."+profile["ca_id"].encode()+b".0.1" not in value
               for value in log_2_messages)

    outer,_=core.certificate_parts((log_2_out/"standalone-0000.der").read_bytes())
    signatures=proof_signatures(outer[2][1][1:])
    assert len(signatures)==2
    subtree_hash=core.root(entries)
    for identity,signature in signatures:
        key_index=[core.relid(value) for value in profile["cosigner_ids"]].index(identity)
        expected=core.H(signer_keys[key_index].read_bytes()+core.message(
            profile["cosigner_ids"][key_index],profile["ca_id"],0,1,
            subtree_hash,0,2))
        wrong_log=core.H(signer_keys[key_index].read_bytes()+core.message(
            profile["cosigner_ids"][key_index],profile["ca_id"],0,1,
            subtree_hash,0,1))
        assert signature==expected and signature!=wrong_log

    mismatched=ExternalCosigner(
        profile["cosigner_ids"][1],signer_keys[1],profile["ca_id"],
        "ecdsa-p256",log=1)
    mismatch_out=temporary/"mismatched"
    try:
        prepare.prepare(
            mismatch_out,temporary,"ecdsa-p256",1,log_number=2,
            external_cosigner=mismatched,external_consistency_proof=[],**common)
    except ValueError as error:
        assert str(error)=="External cosigner issuance log differs from prepare log"
    else:
        raise AssertionError("prepare accepted an external cosigner for another log")
    assert not mismatch_out.exists()

    for invalid in [True,0,65536,"2",None]:
        try:
            prepare.prepare(
                temporary/("invalid-"+str(invalid)),temporary,"ecdsa-p256",1,
                log_number=invalid,**common)
        except ValueError as error:
            assert str(error)=="Invalid issuance log number"
        else:
            raise AssertionError("prepare accepted invalid log_number")

    for invalid in [False,True,0,-1,1<<48,"1",1.0]:
        output=temporary/("invalid-signal-"+str(invalid))
        try:
            prepare.prepare(
                output,temporary,"ecdsa-p256",1,
                signaling_landmark=invalid,**common)
        except ValueError as error:
            assert str(error)=="Invalid MTB2 signaling landmark"
        else:
            raise AssertionError("prepare accepted invalid signaling_landmark")
        assert not output.exists()

print("PASS: prepare issuance-log number propagation")
