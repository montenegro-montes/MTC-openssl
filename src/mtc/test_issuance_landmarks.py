"""Focused persistent per-issuance-log landmark lifecycle tests."""

from pathlib import Path
import tempfile

from issuance_lifecycle import IssuanceLifecycle
from landmarks import Landmark, encode_publication
from local_log import LocalLog


with tempfile.TemporaryDirectory(prefix="mtc-issuance-landmarks-") as temporary:
    root=Path(temporary)/"lifecycle"
    lifecycle=IssuanceLifecycle(root)

    # Every issuance log begins its own sequence at landmark zero.
    assert lifecycle.landmarks(1)==(Landmark(0,0,0),)
    log_1_entries=[b"log-1-entry-0",b"log-1-entry-1"]
    for entry in log_1_entries:lifecycle.append(entry)
    log_1_contents=lifecycle.log(1).state()
    original_landmarks=lifecycle.landmarks(1)

    # The authoritative covered-entry notAfter bound is mandatory and
    # checked before persistent landmark state changes.
    try:
        lifecycle.allocate_landmark(
            2,99,max_covered_not_after=100)
    except ValueError as error:
        assert str(error)=="Landmark expires before covered entries"
    else:
        raise AssertionError("accepted landmark expiring before covered entries")
    assert lifecycle.landmarks(1)==original_landmarks
    assert lifecycle.allocate_landmark(
        1,100,max_covered_not_after=100)==Landmark(1,1,100)
    assert lifecycle.allocate_landmark(
        2,200,max_covered_not_after=150)==Landmark(2,2,200)
    assert lifecycle.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,1,100),Landmark(2,2,200))

    # Selection is newest-active, non-mutating, and returns exactly the
    # log-bound sequence-prefix representation consumed by prepare().
    assert lifecycle.active_landmark_reference(1,50)==(
        1,lifecycle.landmarks(1))
    assert lifecycle.active_landmark_reference(1,50)==(
        lifecycle.landmark_reference(1,2))
    assert lifecycle.active_landmark_reference(1,150)==(
        lifecycle.landmark_reference(1,2))
    assert lifecycle.active_landmark_reference(1,200) is None
    assert lifecycle.landmark_publication(1,150)==encode_publication(
        lifecycle.landmarks(1),150)

    assert lifecycle.rotate()==2
    assert lifecycle.landmarks(2)==(Landmark(0,0,0),)
    assert lifecycle.active_landmark_reference(2,0) is None
    assert lifecycle.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,1,100),Landmark(2,2,200))
    assert lifecycle.active_landmarks(50)==(
        (1,Landmark(1,1,100)),(1,Landmark(2,2,200)))

    lifecycle.append(b"log-2-entry-0")
    assert lifecycle.allocate_landmark(
        1,300,max_covered_not_after=250)==Landmark(1,1,300)
    assert lifecycle.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,300))
    assert lifecycle.landmarks(1)[1].number==1
    assert lifecycle.landmarks(2)[1].number==1

    # Current and historical logs publish independently with the canonical
    # landmarks codec, without changing historical log or landmark state.
    log_1_landmarks=lifecycle.landmarks(1)
    log_2_landmarks=lifecycle.landmarks(2)
    assert lifecycle.landmark_publication(1,150)==encode_publication(
        log_1_landmarks,150)
    assert lifecycle.landmark_publication(2,150)==encode_publication(
        log_2_landmarks,150)
    assert lifecycle.log(1).state()==log_1_contents
    assert lifecycle.landmarks(1)==log_1_landmarks

    # Restart preserves independent numbering and active historical state.
    restarted=IssuanceLifecycle(root)
    assert restarted.current_log_number==2
    assert restarted.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,1,100),Landmark(2,2,200))
    assert restarted.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,300))
    assert restarted.active_landmarks(50)==(
        (1,Landmark(1,1,100)),
        (1,Landmark(2,2,200)),
        (2,Landmark(1,1,300)))
    assert restarted.active_landmark_reference(1,150)==(
        restarted.landmark_reference(1,2))
    assert restarted.active_landmark_reference(2,150)==(
        restarted.landmark_reference(2,1))
    assert restarted.landmark_publication(1,150)==encode_publication(
        restarted.landmarks(1),150)
    assert restarted.landmark_publication(2,150)==encode_publication(
        restarted.landmarks(2),150)

    # Expiration changes only the derived active set.  It never deletes,
    # renumbers, or reassigns a landmark from either log.
    assert restarted.active_landmarks(100)==(
        (1,Landmark(2,2,200)),
        (2,Landmark(1,1,300)))
    assert restarted.active_landmarks(200)==(
        (2,Landmark(1,1,300)),)
    assert restarted.active_landmarks(300)==()
    assert restarted.landmarks(1)==(
        Landmark(0,0,0),Landmark(1,1,100),Landmark(2,2,200))
    assert restarted.landmarks(2)==(
        Landmark(0,0,0),Landmark(1,1,300))
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
