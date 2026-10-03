"""Focused log-aware lifecycle/cosigner synchronization tests."""

from pathlib import Path
import tempfile
from unittest.mock import patch

from cosigner import ExternalCosigner
from issuance import synchronize_cosigner
from issuance_lifecycle import IssuanceLifecycle


IDENTITY="32473.102"
CA_ID="32473.101"
FAMILY="ecdsa-p256"


with tempfile.TemporaryDirectory(prefix="mtc-log-aware-sync-") as temporary:
    temporary=Path(temporary)
    lifecycle=IssuanceLifecycle(temporary/"lifecycle")
    key=temporary/"external.key";key.write_bytes(b"unused-test-key")

    log_1_entries=[b"log-1-entry-0",b"log-1-entry-1"]
    for entry in log_1_entries:lifecycle.append(entry)
    log_1=ExternalCosigner(
        IDENTITY,key,CA_ID,FAMILY,log=1,
        state_path=temporary/"accepted-log-1.json")
    current,proof=synchronize_cosigner(lifecycle.current_log(),log_1)
    assert current["tree_size"]==2 and proof==[]
    assert log_1.accepted.tree_size==2

    for entry in [b"log-1-entry-2",b"log-1-entry-3"]:
        lifecycle.append(entry)
    current,proof=synchronize_cosigner(lifecycle.current_log(),log_1)
    assert current["tree_size"]==4 and proof
    historical=lifecycle.log(1).state()

    assert lifecycle.rotate()==2
    log_2_view=lifecycle.current_log()
    with patch.object(
            log_2_view,"prove_consistency",
            side_effect=AssertionError("cross-log proof attempted")):
        try:
            synchronize_cosigner(log_2_view,log_1)
        except ValueError as error:
            assert str(error)=="cosigner issuance log number mismatch"
        else:
            raise AssertionError("log-1 cosigner accepted for log 2")
    assert lifecycle.log(1).state()==historical

    log_2_entries=[b"log-2-entry-0",b"log-2-entry-1"]
    for entry in log_2_entries:lifecycle.append(entry)
    log_2_state=temporary/"accepted-log-2.json"
    log_2=ExternalCosigner(
        IDENTITY,key,CA_ID,FAMILY,log=2,state_path=log_2_state)
    current,proof=synchronize_cosigner(lifecycle.current_log(),log_2)
    assert current["tree_size"]==2 and proof==[]
    assert log_2.accepted.tree_size==2

    restarted_log_2=ExternalCosigner(
        IDENTITY,key,CA_ID,FAMILY,log=2,state_path=log_2_state)
    lifecycle.append(b"log-2-entry-2")
    current,proof=synchronize_cosigner(
        lifecycle.current_log(),restarted_log_2)
    assert current["tree_size"]==3 and proof
    assert restarted_log_2.accepted.tree_size==3
    assert lifecycle.log(1).state()==historical

print("PASS: log-aware issuance lifecycle cosigner synchronization")
