"""Focused prepare() integration with lifecycle-selected landmarks."""

import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import core
from issuance_lifecycle import IssuanceLifecycle
import prepare


with tempfile.TemporaryDirectory(prefix="mtc-prepare-landmark-lifecycle-") as value:
    temporary=Path(value)
    profile=prepare.crypto_profile("ecdsa-p256")
    original_tbs=core.seq(
        core.der(0xa0,core.integer(2)),core.integer(7),core.ALG,
        core.name(profile["ca_id"]),
        core.seq(core.der(23,b"250101000000Z"),
                 core.der(23,b"490101000000Z")),
        core.seq(),core.seq(core.ALG,core.der(3,b"\0public-key")))
    original=temporary/"original.pem"
    original.write_bytes(core.pem(core.certificate(original_tbs,b"original")))
    signer_keys=[temporary/f"signer-{number}.key" for number in range(2)]
    for number,key in enumerate(signer_keys):
        key.write_bytes(b"key-"+bytes([number]))

    def fake_sign(key,data,family):
        return core.H(Path(key).read_bytes()+data)

    def fake_command(*args,data=None):
        assert args[0]=="pkey" and "-pubout" in args
        key=Path(args[args.index("-in")+1])
        return b"public-"+key.read_bytes()

    lifecycle=IssuanceLifecycle(temporary/"lifecycle")
    lifecycle.append(b"lifecycle-entry-1")
    lifecycle.allocate_landmark(
        1,2_000_000_000,max_covered_not_after=2_000_000_000)
    log_1_reference=lifecycle.landmark_reference(1,1)

    common=dict(
        originals=[original],signer_keys=signer_keys,
        external_consistency_proof=core.consistency([
            core.entry(core.mtc_tbs(
                core.from_pem(original.read_bytes()),profile["ca_id"],0,1))],0))
    with patch.object(prepare,"sign",side_effect=fake_sign), \
         patch.object(prepare,"command",side_effect=fake_command), \
         patch.object(prepare.time,"time",return_value=1_900_000_000), \
         patch.object(prepare.time,"perf_counter",return_value=100.0):
        # The selected log-1 landmark supplies the relative-proof sequence.
        log_1_out=temporary/"log-1"
        meta_1=prepare.prepare(
            log_1_out,temporary,"ecdsa-p256",1,
            landmark_reference=log_1_reference,**common)
        assert (log_1_out/"landmark-0000.der").is_file()
        assert meta_1["landmarks"]==[0,1]
        assert meta_1["latest_landmark"]==1
        assert (log_1_out/"landmarks.txt").read_text()==(
            "1\n1 2000000000\n0 0\n")

        # Rotation owns a fresh log-2 sequence beginning at landmark zero.
        assert lifecycle.rotate()==2
        log_2_reference=lifecycle.landmark_reference(2,0)
        log_2_out=temporary/"log-2"
        meta_2=prepare.prepare(
            log_2_out,temporary,"ecdsa-p256",1,log_number=2,
            landmark_reference=log_2_reference,**common)
        assert (log_2_out/"standalone-0000.der").is_file()
        assert not (log_2_out/"landmark-0000.der").exists()
        assert meta_2["landmarks"]==[0]
        assert meta_2["latest_landmark"]==0
        assert meta_2["mtc_modes"]==["standalone"]
        assert (log_2_out/"landmarks.txt").read_text()=="0\n0 0\n"

        # The log binding is checked before output generation or signing.
        rejected=temporary/"cross-log"
        try:
            prepare.prepare(
                rejected,temporary,"ecdsa-p256",1,log_number=2,
                landmark_reference=log_1_reference,**common)
        except ValueError as error:
            assert str(error)==(
                "Lifecycle landmark issuance log differs from prepare log")
        else:
            raise AssertionError("prepare accepted a cross-log landmark")
        assert not rejected.exists()

        # Omitting the optional reference retains the legacy initial landmark.
        legacy=temporary/"legacy"
        legacy_meta=prepare.prepare(
            legacy,temporary,"ecdsa-p256",1,
            originals=[original],signer_keys=signer_keys)
        assert (legacy/"landmark-0000.der").is_file()
        assert legacy_meta["landmarks"]==[0,1]
        assert legacy_meta["latest_landmark"]==1
        assert json.loads((legacy/"manifest.json").read_text())[
            "mtc_modes"]==["landmark","standalone"]

print("PASS: prepare consumes log-bound lifecycle landmarks")
