"""Persistent CA-side lifecycle for draft-06 issuance logs."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile

from core import root
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
                LocalLog(self._log_path(1))
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
        if (set(path.name for path in self.root.iterdir())
                != {"lifecycle.json","logs"}
                or state_path.is_symlink() or not state_path.is_file()
                or logs_path.is_symlink() or not logs_path.is_dir()):
            raise ValueError("Invalid issuance lifecycle layout")
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
        actual=set()
        for path in logs_path.iterdir():
            if path.is_symlink() or not path.is_dir():
                raise ValueError("Invalid issuance lifecycle log directory")
            actual.add(path.name)
        following=current+1
        recoverable=(
            recover_rotation and current<MAX_LOG_NUMBER
            and actual==expected|{f"{following:05d}"})
        if recoverable:
            future=LocalLog(self._log_path(following))
            if future.state()!={
                    "tree_size":0,
                    "hash":root([]).hex()}:
                raise ValueError("Unexpected future issuance log is not empty")
        elif actual!=expected:
            raise ValueError("Issuance lifecycle logs contradict state")
        for number in range(1,current+1):
            LocalLog(self._log_path(number))
        if recoverable:
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
            self._publish(following)
            return following
