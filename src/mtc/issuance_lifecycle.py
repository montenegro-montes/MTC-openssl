"""Persistent CA-side lifecycle for draft-07 issuance logs."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile

from core import root
from landmarks import Landmark, active, encode_publication, validate_sequence
from local_log import LocalLog


MAX_LOG_NUMBER = 65535


class IssuanceLogView:
    """Read-only access to one LocalLog through an IssuanceLifecycle."""

    def __init__(self, log_number, log):
        self.log_number = log_number
        self._log = log

    @property
    def directory(self):
        return self._log.directory

    def state(self):
        return self._log.state()

    def get_entry(self, index):
        return self._log.get_entry(index)

    def inclusion_proof(self, index, size):
        return self._log.inclusion_proof(index, size)

    def consistency_proof(self, old, new):
        return self._log.consistency_proof(old, new)

    def subtree_proof(self, start, end, size):
        return self._log.subtree_proof(start, end, size)

    def prove_consistency(self, old_state):
        return self._log.prove_consistency(old_state)


class IssuanceLifecycle:
    """Select the single issuance log to which the CA may append."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("Lifecycle root must be a directory")
        with self._locked():
            contents=list(self.root.iterdir())
            if not contents:
                (self.root/"logs").mkdir()
                (self.root/"landmarks").mkdir()
                LocalLog(self._log_path(1))
                self._publish_landmarks(1,[Landmark(0,0,0)])
                self._publish(1)
            self._read(recover_rotation=True)

    @contextmanager
    def _locked(self):
        descriptor=os.open(self.root,os.O_RDONLY)
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_log_number(log_number):
        if type(log_number) is not int or not 1<=log_number<=MAX_LOG_NUMBER:
            raise ValueError("Invalid issuance log number")

    def _log_path(self,log_number):
        return self.root/"logs"/f"{log_number:05d}"

    def _landmark_path(self,log_number):
        return self.root/"landmarks"/f"{log_number:05d}.json"

    def _publish_landmarks(self,log_number,sequence):
        self._validate_log_number(log_number)
        validate_sequence(sequence)
        data=json.dumps({
            "log_number":log_number,
            "landmarks":[{
                "number":landmark.number,
                "tree_size":landmark.tree_size,
                "expiration":landmark.expiration,
            } for landmark in sequence],
        },separators=(",",":")) + "\n"
        directory=self.root/"landmarks"
        descriptor,temporary=tempfile.mkstemp(
            prefix=f".{log_number:05d}-",dir=directory)
        try:
            with os.fdopen(descriptor,"w",encoding="utf-8") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary,self._landmark_path(log_number))
            directory_descriptor=os.open(directory,os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _read_landmarks(self,log_number):
        self._validate_log_number(log_number)
        path=self._landmark_path(log_number)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid issuance-log landmark state")
        try:
            state=json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(state,dict)
                    or set(state)!={"log_number","landmarks"}
                    or type(state["log_number"]) is not int
                    or state["log_number"]!=log_number
                    or not isinstance(state["landmarks"],list)):
                raise ValueError
            sequence=[]
            for value in state["landmarks"]:
                if (not isinstance(value,dict)
                        or set(value)!={"number","tree_size","expiration"}
                        or any(type(value[field]) is not int for field in value)):
                    raise ValueError
                sequence.append(Landmark(
                    value["number"],value["tree_size"],value["expiration"]))
            validate_sequence(sequence)
        except (OSError,UnicodeError,json.JSONDecodeError,ValueError) as error:
            raise ValueError("Invalid issuance-log landmark state") from error
        return sequence

    def _publish(self,current_log_number):
        data=json.dumps(
            {"current_log_number":current_log_number},
            separators=(",",":")) + "\n"
        descriptor,temporary=tempfile.mkstemp(
            prefix=".lifecycle-",dir=self.root)
        try:
            with os.fdopen(descriptor,"w",encoding="utf-8") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary,self.root/"lifecycle.json")
            directory=os.open(self.root,os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _read(self,recover_rotation=False):
        state_path=self.root/"lifecycle.json"
        logs_path=self.root/"logs"
        landmarks_path=self.root/"landmarks"
        if (set(path.name for path in self.root.iterdir())
                != {"lifecycle.json","logs","landmarks"}
                or state_path.is_symlink() or not state_path.is_file()
                or logs_path.is_symlink() or not logs_path.is_dir()):
            raise ValueError("Invalid issuance lifecycle layout")
        if landmarks_path.is_symlink() or not landmarks_path.is_dir():
            raise ValueError("Invalid issuance lifecycle landmark layout")
        try:
            state=json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError,UnicodeError,json.JSONDecodeError) as error:
            raise ValueError("Invalid issuance lifecycle state") from error
        if (not isinstance(state,dict)
                or set(state)!={"current_log_number"}):
            raise ValueError("Invalid issuance lifecycle state")
        current=state["current_log_number"]
        self._validate_log_number(current)
        expected={f"{number:05d}" for number in range(1,current+1)}
        expected_landmarks={name+".json" for name in expected}
        actual=set()
        for path in logs_path.iterdir():
            if path.is_symlink() or not path.is_dir():
                raise ValueError("Invalid issuance lifecycle log directory")
            actual.add(path.name)
        actual_landmarks=set()
        for path in landmarks_path.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError("Invalid issuance lifecycle landmark file")
            actual_landmarks.add(path.name)
        following=current+1
        following_name=f"{following:05d}"
        recoverable_without_landmarks=(
            recover_rotation and current<MAX_LOG_NUMBER
            and actual==expected|{following_name}
            and actual_landmarks==expected_landmarks)
        recoverable_with_landmarks=(
            recover_rotation and current<MAX_LOG_NUMBER
            and actual==expected|{following_name}
            and actual_landmarks==expected_landmarks|{following_name+".json"})
        recoverable=recoverable_without_landmarks or recoverable_with_landmarks
        if recoverable:
            future=LocalLog(self._log_path(following))
            if future.state()!={
                    "tree_size":0,
                    "hash":root([]).hex()}:
                raise ValueError("Unexpected future issuance log is not empty")
            if recoverable_with_landmarks and self._read_landmarks(following)!=[
                    Landmark(0,0,0)]:
                raise ValueError("Unexpected future landmark sequence")
        elif actual!=expected or actual_landmarks!=expected_landmarks:
            raise ValueError("Issuance lifecycle logs contradict state")
        for number in range(1,current+1):
            LocalLog(self._log_path(number))
            self._read_landmarks(number)
        if recoverable:
            if recoverable_without_landmarks:
                self._publish_landmarks(following,[Landmark(0,0,0)])
            self._publish(following)
            return following
        return current

    @property
    def current_log_number(self):
        with self._locked():
            return self._read()

    def log(self,log_number):
        self._validate_log_number(log_number)
        with self._locked():
            current=self._read()
            if log_number>current:
                raise KeyError("Issuance log does not exist")
            return IssuanceLogView(
                log_number,LocalLog(self._log_path(log_number)))

    def current_log(self):
        with self._locked():
            current=self._read()
            return IssuanceLogView(current,LocalLog(self._log_path(current)))

    def append(self,entry,*,log_number=None):
        with self._locked():
            current=self._read()
            selected=current if log_number is None else log_number
            self._validate_log_number(selected)
            if selected!=current:
                raise ValueError("Cannot append to a non-current issuance log")
            return LocalLog(self._log_path(current)).append(entry)

    def landmarks(self,log_number):
        self._validate_log_number(log_number)
        with self._locked():
            current=self._read()
            if log_number>current:
                raise KeyError("Issuance log does not exist")
            return tuple(self._read_landmarks(log_number))

    def landmark_reference(self,log_number,number=None):
        """Return a log-bound, immutable sequence ending at one landmark."""
        sequence=self.landmarks(log_number)
        selected=len(sequence)-1 if number is None else number
        if type(selected) is not int or not 0<=selected<len(sequence):
            raise ValueError("Invalid landmark number")
        return log_number,sequence[:selected+1]

    def allocate_landmark(
            self,tree_size,expiration,*,max_covered_not_after):
        with self._locked():
            if (type(tree_size) is not int or type(expiration) is not int
                    or type(max_covered_not_after) is not int
                    or max_covered_not_after<0):
                raise ValueError("Invalid landmark")
            if expiration<max_covered_not_after:
                raise ValueError("Landmark expires before covered entries")
            current=self._read()
            log_state=LocalLog(self._log_path(current)).state()
            if not 0<tree_size<=log_state["tree_size"]:
                raise ValueError("Landmark exceeds current issuance log")
            sequence=self._read_landmarks(current)
            landmark=Landmark(len(sequence),tree_size,expiration)
            updated=sequence+[landmark]
            validate_sequence(updated)
            self._publish_landmarks(current,updated)
            return landmark

    def active_landmark_reference(self,log_number,now):
        """Return the newest active landmark as a prepare-compatible reference."""
        sequence=self.landmarks(log_number)
        candidates=active(sequence,now)
        if not candidates:
            return None
        return log_number,sequence[:candidates[-1].number+1]

    def landmark_publication(self,log_number,now):
        """Return the canonical draft-07 publication for one issuance log."""
        return encode_publication(self.landmarks(log_number),now)

    def active_landmarks(self,now):
        with self._locked():
            current=self._read()
            values=[]
            for log_number in range(1,current+1):
                values.extend(
                    (log_number,landmark)
                    for landmark in active(self._read_landmarks(log_number),now))
            return tuple(values)

    def rotate(self):
        with self._locked():
            current=self._read()
            if current==MAX_LOG_NUMBER:
                raise ValueError("Maximum issuance log number reached")
            following=current+1
            path=self._log_path(following)
            if path.exists() or path.is_symlink():
                raise ValueError("Next issuance log already exists")
            LocalLog(path)
            self._publish_landmarks(following,[Landmark(0,0,0)])
            self._publish(following)
            return following
