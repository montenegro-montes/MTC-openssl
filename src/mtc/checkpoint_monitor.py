"""Continuous fail-closed monitoring of authenticated MTC checkpoints."""

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
from threading import Event
from urllib.parse import urlsplit

from rp_updater import (
    RPHTTPError,
    _checkpoint,
    advance_checkpoint,
    fetch_authenticated_checkpoint,
)


class MonitorStateError(ValueError):
    pass


class CheckpointStateStore:
    """Persist exactly one authenticated checkpoint using atomic replacement."""

    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.exists() and self.directory.is_symlink():
            raise MonitorStateError("monitor state directory must not be a symlink")
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise MonitorStateError("monitor state path is not a directory")
        self.path = self.directory / "checkpoint.json"

    @staticmethod
    def _validate(value):
        try:
            checkpoint = dict(_checkpoint(value))
        except ValueError as error:
            raise MonitorStateError("invalid monitor checkpoint") from error
        if bytes.fromhex(checkpoint["hash"]).hex() != checkpoint["hash"]:
            raise MonitorStateError("invalid monitor checkpoint")
        return checkpoint

    def load(self):
        contents = list(self.directory.iterdir())
        if not contents:
            return None
        if len(contents) != 1 or contents[0].name != self.path.name:
            raise MonitorStateError("invalid monitor state layout")
        try:
            info = self.path.lstat()
        except OSError as error:
            raise MonitorStateError("unable to inspect monitor state") from error
        if not stat.S_ISREG(info.st_mode):
            raise MonitorStateError("monitor checkpoint must be a regular file")
        try:
            value = json.loads(self.path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise MonitorStateError("invalid monitor checkpoint") from error
        return self._validate(value)

    def save(self, checkpoint):
        checkpoint = self._validate(checkpoint)
        data = (json.dumps(
            checkpoint, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".checkpoint-", dir=self.directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()
        return checkpoint


def _result(result, severity, previous=None, candidate=None):
    return {
        "result": result,
        "severity": severity,
        "previous": previous,
        "candidate": candidate,
    }


class CheckpointMonitor:
    def __init__(self, log_url, trusted_authority, checker, state_directory,
                 fetch_checkpoint=fetch_authenticated_checkpoint,
                 advance=advance_checkpoint):
        self.log_url = require_http_log_url(log_url)
        self.trusted_authority = Path(trusted_authority)
        self.checker = Path(checker)
        self.store = CheckpointStateStore(state_directory)
        self.fetch_checkpoint = fetch_checkpoint
        self.advance = advance

    def check_once(self):
        try:
            previous = self.store.load()
        except MonitorStateError:
            return _result("STATE", "ERROR")

        try:
            candidate = self.fetch_checkpoint(
                self.log_url, self.trusted_authority, self.checker)
        except RPHTTPError:
            return _result("UNAVAILABLE", "ERROR", previous=previous)
        except (ValueError, OSError):
            return _result("AUTHENTICATION", "ALERT", previous=previous)

        try:
            candidate = self.store._validate(candidate)
        except MonitorStateError:
            return _result("AUTHENTICATION", "ALERT", previous=previous)

        if previous is None:
            try:
                self.store.save(candidate)
            except (MonitorStateError, OSError):
                return _result("STATE", "ERROR", candidate=candidate)
            return _result("INITIAL", "PASS", candidate=candidate)

        if candidate["log_number"] != previous["log_number"]:
            return _result(
                "CONSISTENCY", "ALERT", previous=previous, candidate=candidate)
        if candidate["tree_size"] < previous["tree_size"]:
            return _result(
                "ROLLBACK", "ALERT", previous=previous, candidate=candidate)
        if candidate["tree_size"] == previous["tree_size"]:
            if candidate["hash"] == previous["hash"]:
                return _result(
                    "UNCHANGED", "PASS", previous=previous, candidate=candidate)
            return _result(
                "CONSISTENCY", "ALERT", previous=previous, candidate=candidate)

        try:
            advanced = self.advance(self.log_url, previous, candidate)
        except RPHTTPError:
            return _result(
                "UNAVAILABLE", "ERROR", previous=previous, candidate=candidate)
        except (ValueError, OSError):
            return _result(
                "CONSISTENCY", "ALERT", previous=previous, candidate=candidate)
        if advanced != candidate:
            return _result(
                "CONSISTENCY", "ALERT", previous=previous, candidate=candidate)
        try:
            self.store.save(candidate)
        except (MonitorStateError, OSError):
            return _result("STATE", "ERROR", previous=previous, candidate=candidate)
        result = _result(
            "ADVANCE", "PASS", previous=previous, candidate=candidate)
        result.update({
            "consistency_verified": True,
            "consistency_old_size": previous["tree_size"],
            "consistency_new_size": candidate["tree_size"],
        })
        return result


def require_http_log_url(value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "http" and parsed.hostname
                 and parsed.port is not None
                 and parsed.username is None and parsed.password is None
                 and parsed.path in ("", "/")
                 and not parsed.query and not parsed.fragment)
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("log URL must be an explicit http://host:port/ URL")
    return value.rstrip("/") + "/"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-url", required=True)
    parser.add_argument("--trusted-authority", type=Path, required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument(
        "--state-directory", type=Path,
        default=Path("/var/lib/mtc-monitor"))
    parser.add_argument("--interval", type=float, default=60.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval must be positive")
    try:
        monitor = CheckpointMonitor(
            args.log_url, args.trusted_authority, args.checker,
            args.state_directory)
    except (ValueError, OSError) as error:
        parser.error(str(error))

    stopped = Event()

    def stop(signum, frame):
        stopped.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)

    while not stopped.is_set():
        result = monitor.check_once()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        if args.once:
            return 0 if result["severity"] == "PASS" else 1
        stopped.wait(args.interval)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
