"""Focused tests for the persistent CA-side issuance-log lifecycle."""

import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import core
from issuance_lifecycle import IssuanceLifecycle
from local_log import LocalLog


def rejected(call,message=None):
    try:
        call()
    except (KeyError,ValueError) as error:
        if message is not None:assert str(error)==message
    else:
        raise AssertionError("operation should have been rejected")


with tempfile.TemporaryDirectory(prefix="mtc-issuance-lifecycle-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)
    assert lifecycle.current_log_number==1
    assert lifecycle.current_log().log_number==1
    assert lifecycle.log(1).state()=={
        "tree_size":0,"hash":core.root([]).hex()}
    assert sorted(path.name for path in (root/"logs").iterdir())==["00001"]
    rejected(lambda:lifecycle.log(2))

    first_entries=[b"log-1-entry-0",b"log-1-entry-1"]
    for entry in first_entries:lifecycle.append(entry)
    log_1_before=lifecycle.log(1).state()
    assert log_1_before=={
        "tree_size":2,"hash":core.root(first_entries).hex()}

    assert lifecycle.rotate()==2
    assert lifecycle.current_log_number==2
    assert lifecycle.current_log().state()=={
        "tree_size":0,"hash":core.root([]).hex()}
    assert lifecycle.log(1).state()==log_1_before
    assert [lifecycle.log(1).get_entry(i) for i in range(2)]==first_entries

    lifecycle.append(b"log-2-entry")
    assert lifecycle.log(2).state()=={
        "tree_size":1,"hash":core.root([b"log-2-entry"]).hex()}
    assert lifecycle.log(1).state()==log_1_before
    rejected(
        lambda:lifecycle.append(b"historical",log_number=1),
        "Cannot append to a non-current issuance log")
    assert lifecycle.log(1).state()==log_1_before

    restarted=IssuanceLifecycle(root)
    assert restarted.current_log_number==2
    assert restarted.log(1).state()==log_1_before
    assert restarted.log(2).get_entry(0)==b"log-2-entry"
    assert restarted.rotate()==3
    assert restarted.current_log_number==3
    assert restarted.log(3).state()=={
        "tree_size":0,"hash":core.root([]).hex()}
    assert restarted.log(1).state()==log_1_before

    # Exercise the actual rotate() maximum guard without creating 65,535
    # directories; _read() is the trusted source used by rotate().
    with patch.object(restarted,"_read",return_value=65535):
        rejected(
            restarted.rotate,"Maximum issuance log number reached")


# Recover the exact crash window after creation of an empty N+1 but before the
# lifecycle.json rename.  The historical log is never changed.
with tempfile.TemporaryDirectory(prefix="mtc-lifecycle-recovery-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)
    lifecycle.append(b"historical-entry")
    historical=lifecycle.log(1).state()
    LocalLog(root/"logs"/"00002")
    assert json.loads((root/"lifecycle.json").read_text())=={
        "current_log_number":1}

    recovered=IssuanceLifecycle(root)
    assert recovered.current_log_number==2
    assert recovered.log(2).state()=={
        "tree_size":0,"hash":core.root([]).hex()}
    assert recovered.log(1).state()==historical
    assert recovered.log(1).get_entry(0)==b"historical-entry"

    # Normal operation and restart continue after recovery.
    recovered.append(b"new-current-entry")
    restarted=IssuanceLifecycle(root)
    assert restarted.current_log_number==2
    assert restarted.log(2).get_entry(0)==b"new-current-entry"
    assert restarted.log(1).state()==historical


# A non-empty unexpected N+1 is ambiguous and must neither be accepted nor
# deleted.  lifecycle.json and the historical log remain unchanged.
with tempfile.TemporaryDirectory(prefix="mtc-lifecycle-ambiguous-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)
    lifecycle.append(b"historical-entry")
    historical=lifecycle.log(1).state()
    future=LocalLog(root/"logs"/"00002")
    future.append(b"unexpected-future-entry")
    lifecycle_bytes=(root/"lifecycle.json").read_bytes()
    future_state=future.state()

    rejected(
        lambda:IssuanceLifecycle(root),
        "Unexpected future issuance log is not empty")
    assert (root/"lifecycle.json").read_bytes()==lifecycle_bytes
    assert LocalLog(root/"logs"/"00001").state()==historical
    assert LocalLog(root/"logs"/"00002").state()==future_state
    assert LocalLog(root/"logs"/"00002").get_entry(0)==b"unexpected-future-entry"


def malformed(layout,state=b'{"current_log_number":1}\n'):
    with tempfile.TemporaryDirectory(prefix="mtc-lifecycle-invalid-") as temporary:
        root=Path(temporary)/"lifecycle";root.mkdir()
        (root/"logs").mkdir()
        (root/"landmarks").mkdir()
        if layout:
            for number in layout:
                LocalLog(root/"logs"/f"{number:05d}")
                (root/"landmarks"/f"{number:05d}.json").write_text(
                    json.dumps({
                        "log_number":number,
                        "landmarks":[{
                            "number":0,"tree_size":0,"expiration":0,
                        }],
                    },separators=(",",":")) + "\n")
        (root/"lifecycle.json").write_bytes(state)
        before={path.relative_to(root):path.read_bytes()
                for path in root.rglob("*") if path.is_file()}
        rejected(lambda:IssuanceLifecycle(root))
        after={path.relative_to(root):path.read_bytes()
               for path in root.rglob("*") if path.is_file()}
        assert after==before


malformed([1],b"not json")
malformed([1],b'{}')
malformed([1],b'{"current_log_number":true}')
malformed([1],b'{"current_log_number":0}')
malformed([1],b'{"current_log_number":65536}')
malformed([1],b'{"current_log_number":1,"extra":0}')
malformed([1,2,3],b'{"current_log_number":1}')  # detectable rollback/ambiguity
malformed([1],b'{"current_log_number":2}')    # missing current log
malformed([2],b'{"current_log_number":2}')    # missing historical log 1

print("PASS: persistent issuance-log lifecycle")
