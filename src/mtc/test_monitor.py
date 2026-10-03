"""Focused independent issuance-log mirror tests."""

from pathlib import Path
import tempfile
from threading import Thread

from core import root
from log_service import LogServer
from monitor import IssuanceLogMonitor, MonitorError


class RunningLog:
    def __init__(self,directory,entries):
        self.server=LogServer(("127.0.0.1",0),directory,read_only=True)
        for entry in entries:self.server.log.append(entry)
        self.thread=Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.url=f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


def checkpoint(entries,size):
    return {"tree_size":size,"hash":root(entries[:size]).hex()}


def rejected_without_change(monitor,log_number,state,operation):
    before_entries=[monitor.entry(log_number,index)
                    for index in range(state["tree_size"])]
    try:operation()
    except MonitorError:pass
    else:raise AssertionError("monitor accepted invalid update")
    assert monitor.state(log_number)==state
    assert [monitor.entry(log_number,index)
            for index in range(state["tree_size"])]==before_entries


with tempfile.TemporaryDirectory(prefix="mtc-monitor-") as value:
    temporary=Path(value)
    entries=[f"log-1-entry-{index}".encode() for index in range(14)]
    remote=RunningLog(temporary/"remote-1",entries[:3])
    monitor=IssuanceLogMonitor(temporary/"mirror")
    try:
        # Empty -> 3, then 3 -> 8.
        assert monitor.update(1,remote.url,checkpoint(entries,3))==checkpoint(entries,3)
        for entry in entries[3:8]:remote.server.log.append(entry)
        assert monitor.update(1,remote.url,checkpoint(entries,8))==checkpoint(entries,8)

        # Restart persistence, then 8 -> 12.
        monitor=IssuanceLogMonitor(temporary/"mirror")
        for entry in entries[8:12]:remote.server.log.append(entry)
        state_12=checkpoint(entries,12)
        assert monitor.update(1,remote.url,state_12)==state_12
        assert [monitor.entry(1,index) for index in range(12)]==entries[:12]

        # Same-size identity is local-only: it still succeeds after shutdown.
        remote.close()
        assert monitor.update(1,remote.url,state_12)==state_12

        rejected_without_change(
            monitor,1,state_12,
            lambda:monitor.update(1,remote.url,checkpoint(entries,8)))
        conflict={"tree_size":12,"hash":("00"*32)}
        rejected_without_change(
            monitor,1,state_12,
            lambda:monitor.update(1,remote.url,conflict))
    finally:
        if remote.thread.is_alive():remote.close()

    # Corrupted consistency proof leaves the previously accepted mirror intact.
    remote=RunningLog(temporary/"remote-proof",entries[:13])
    original_proof=remote.server.log.consistency_proof
    def corrupt_proof(old,new):
        value=original_proof(old,new)
        value["proof"]=["00"*32]+value["proof"][1:]
        return value
    remote.server.log.consistency_proof=corrupt_proof
    try:
        rejected_without_change(
            monitor,1,state_12,
            lambda:monitor.update(1,remote.url,checkpoint(entries,13)))
    finally:remote.close()

    # A modified downloaded entry passes HTTP framing but not root reconstruction.
    remote=RunningLog(temporary/"remote-entry",entries[:13])
    original_entry=remote.server.log.get_entry
    remote.server.log.get_entry=lambda index:(
        b"modified-entry" if index==12 else original_entry(index))
    try:
        rejected_without_change(
            monitor,1,state_12,
            lambda:monitor.update(1,remote.url,checkpoint(entries,13)))
    finally:remote.close()

    # An authenticated candidate root different from the remote tree is rejected.
    remote=RunningLog(temporary/"remote-root",entries[:13])
    different={"tree_size":13,"hash":root(entries[:12]+[b"other"]).hex()}
    try:
        rejected_without_change(
            monitor,1,state_12,
            lambda:monitor.update(1,remote.url,different))
    finally:remote.close()

    # Log 2 starts from its own empty root; no log-1 consistency base is used.
    log_1_state=monitor.state(1)
    log_2_entries=[b"log-2-entry-0",b"log-2-entry-1"]
    remote=RunningLog(temporary/"remote-2",log_2_entries)
    original_proof=remote.server.log.consistency_proof
    requests=[]
    def record_proof(old,new):
        requests.append((old,new))
        return original_proof(old,new)
    remote.server.log.consistency_proof=record_proof
    try:
        expected=checkpoint(log_2_entries,2)
        assert monitor.update(2,remote.url,expected)==expected
        assert requests==[(0,2)]
    finally:remote.close()
    assert monitor.state(1)==log_1_state
    assert [monitor.entry(1,index) for index in range(12)]==entries[:12]

print("PASS: independent issuance-log mirror")
