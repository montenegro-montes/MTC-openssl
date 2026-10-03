"""Focused persistent per-issuance-log landmark lifecycle tests."""

from pathlib import Path
import tempfile

from issuance_lifecycle import IssuanceLifecycle
from landmarks import Landmark
from local_log import LocalLog


with tempfile.TemporaryDirectory(prefix="mtc-issuance-landmarks-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)

    # Every issuance log begins its own sequence at landmark zero.
    assert lifecycle.landmarks(1)==(Landmark(0,0,0),)
    log_1_entries=[b"log-1-entry-0",b"log-1-entry-1"]
    for entry in log_1_entries:lifecycle.append(entry)
    log_1_contents=lifecycle.log(1).state()
    assert lifecycle.allocate_landmark(2,100)==Landmark(1,2,100)
    assert lifecycle.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,2,100))

    assert lifecycle.rotate()==2
    assert lifecycle.landmarks(2)==(Landmark(0,0,0),)
    assert lifecycle.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,2,100))
    assert lifecycle.active_landmarks(50)==((1,Landmark(1,2,100)),)

    lifecycle.append(b"log-2-entry-0")
    assert lifecycle.allocate_landmark(1,200)==Landmark(1,1,200)
    assert lifecycle.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,200))
    assert lifecycle.landmarks(1)[1].number==1
    assert lifecycle.landmarks(2)[1].number==1

    # Restart preserves independent numbering and active historical state.
    restarted=IssuanceLifecycle(root)
    assert restarted.current_log_number==2
    assert restarted.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,2,100))
    assert restarted.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,200))
    assert restarted.active_landmarks(50)==(
        (1,Landmark(1,2,100)),
        (2,Landmark(1,1,200)))

    # Expiration changes only the derived active set.  It never deletes,
    # renumbers, or reassigns a landmark from either log.
    assert restarted.active_landmarks(100)==(
        (2,Landmark(1,1,200)),)
    assert restarted.active_landmarks(200)==()
    assert restarted.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,2,100))
    assert restarted.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,200))
    assert restarted.log(1).state()==log_1_contents
    assert [restarted.log(1).get_entry(i) for i in range(2)]==log_1_entries

print("PASS: per-issuance-log persistent landmark lifecycle")


# Recover the second exact rotation crash window: N+1 and its landmark-zero
# state are durable, but lifecycle.json still names N.
with tempfile.TemporaryDirectory(prefix="mtc-landmark-rotation-recovery-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)
    LocalLog(root/"logs"/"00002")
    lifecycle._publish_landmarks(2,[Landmark(0,0,0)])
    recovered=IssuanceLifecycle(root)
    assert recovered.current_log_number==2
    assert recovered.landmarks(1)==(Landmark(0,0,0),)
    assert recovered.landmarks(2)==(Landmark(0,0,0),)

print("PASS: landmark rotation crash recovery")
