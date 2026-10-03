"""Fail-closed persistent relying-party state publication."""

import hashlib
import json
import os
from pathlib import Path
import tempfile

from trusted_subtrees import decode_trusted_subtrees


def _checkpoint(state):
    if (not isinstance(state, dict)
            or set(state) != {"log_number", "tree_size", "hash"}
            or type(state["log_number"]) is not int
            or not 1 <= state["log_number"] <= 65535
            or type(state["tree_size"]) is not int
            or not 0 <= state["tree_size"] < 1 << 48
            or not isinstance(state["hash"], str)
            or len(state["hash"]) != 64):
        raise ValueError("invalid checkpoint")

    try:
        root_hash = bytes.fromhex(state["hash"])
    except ValueError as exc:
        raise ValueError("invalid checkpoint") from exc

    if len(root_hash) != 32 or root_hash.hex() != state["hash"]:
        raise ValueError("invalid checkpoint")

    return dict(state)


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RPStateStore:
    """Publish checkpoint + MTS1 as one atomically selected generation."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.generations = self.directory / "generations"
        self.current = self.directory / "current"

        if self.directory.exists() and self.directory.is_symlink():
            raise ValueError("RP state directory must not be a symlink")

        self.generations.mkdir(parents=True, exist_ok=True)

        if self.generations.is_symlink():
            raise ValueError("generations directory must not be a symlink")

        if not self.directory.is_dir() or not self.generations.is_dir():
            raise ValueError("invalid RP state directory")

    @staticmethod
    def _generation_name(checkpoint, trusted_subtrees):
        return "%05d-%016d-%s-%s" % (
            checkpoint["log_number"],
            checkpoint["tree_size"],
            checkpoint["hash"],
            hashlib.sha256(trusted_subtrees).hexdigest(),
        )

    @staticmethod
    def _write_file(path, data):
        with open(path, "xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

    @staticmethod
    def _checkpoint_bytes(checkpoint):
        return (
            json.dumps(
                checkpoint,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
        ).encode("ascii")

    @staticmethod
    def _read_generation(path):
        if path.is_symlink() or not path.is_dir():
            raise ValueError("invalid RP generation")

        checkpoint_path = path / "checkpoint.json"
        mts1_path = path / "trusted-subtrees.mts1"

        if (checkpoint_path.is_symlink()
                or mts1_path.is_symlink()
                or not checkpoint_path.is_file()
                or not mts1_path.is_file()):
            raise ValueError("invalid RP generation")

        try:
            checkpoint = json.loads(
                checkpoint_path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid RP checkpoint") from exc

        checkpoint = _checkpoint(checkpoint)

        try:
            mts1 = mts1_path.read_bytes()
        except OSError as exc:
            raise ValueError("invalid RP trusted-subtree state") from exc

        # Full structural and log-domain validation before a generation can
        # be selected.
        subtrees = decode_trusted_subtrees(mts1)
        if any(
                subtree.log_number != checkpoint["log_number"]
                for subtree in subtrees):
            raise ValueError(
                "RP trusted-subtree state differs from checkpoint issuance log"
            )

        return checkpoint, mts1

    def load_current(self):
        if not self.current.exists():
            if self.current.is_symlink():
                raise ValueError("broken current RP state")
            return None

        if not self.current.is_symlink():
            raise ValueError("current RP state is not a symlink")

        try:
            target = os.readlink(self.current)
        except OSError as exc:
            raise ValueError("invalid current RP state") from exc

        target_path = Path(target)
        if target_path.is_absolute():
            raise ValueError("absolute current RP state target")

        resolved = (self.directory / target_path).resolve()
        generations = self.generations.resolve()

        try:
            resolved.relative_to(generations)
        except ValueError as exc:
            raise ValueError("current RP state escapes generations") from exc

        checkpoint, mts1 = self._read_generation(resolved)

        expected = self._generation_name(checkpoint, mts1)
        if resolved.name != expected:
            raise ValueError("generation name does not match checkpoint")

        return {
            "checkpoint": checkpoint,
            "trusted_subtrees": mts1,
            "path": resolved,
        }

    def publish(self, checkpoint, trusted_subtrees):
        checkpoint = _checkpoint(checkpoint)

        if not isinstance(trusted_subtrees, bytes):
            raise ValueError("trusted-subtree state must be bytes")

        # Reject malformed or cross-log MTS1 before touching persistent state.
        subtrees = decode_trusted_subtrees(trusted_subtrees)
        if any(
                subtree.log_number != checkpoint["log_number"]
                for subtree in subtrees):
            raise ValueError(
                "RP trusted-subtree state differs from checkpoint issuance log"
            )

        name = self._generation_name(checkpoint, trusted_subtrees)
        final = self.generations / name

        if final.exists() or final.is_symlink():
            existing_checkpoint, existing_mts1 = self._read_generation(final)
            if (existing_checkpoint != checkpoint
                    or existing_mts1 != trusted_subtrees):
                raise ValueError("generation already exists with other data")
        else:
            temporary = Path(tempfile.mkdtemp(
                prefix=".generation-",
                dir=self.generations,
            ))

            try:
                self._write_file(
                    temporary / "checkpoint.json",
                    self._checkpoint_bytes(checkpoint),
                )
                self._write_file(
                    temporary / "trusted-subtrees.mts1",
                    trusted_subtrees,
                )

                # Re-read exactly what would become visible.
                written_checkpoint, written_mts1 = self._read_generation(
                    temporary)
                if (written_checkpoint != checkpoint
                        or written_mts1 != trusted_subtrees):
                    raise ValueError("RP generation validation failed")

                _fsync_directory(temporary)
                os.rename(temporary, final)
                _fsync_directory(self.generations)
            except Exception:
                if temporary.exists():
                    for child in temporary.iterdir():
                        child.unlink()
                    temporary.rmdir()
                raise

        # Build a relative selector so the state directory remains relocatable.
        target = Path("generations") / name

        # Reserve a unique selector name in the same directory as current so
        # the final os.replace() remains an atomic same-filesystem operation.
        fd, selector_name = tempfile.mkstemp(
            prefix=".current-",
            dir=self.directory,
        )
        os.close(fd)
        selector = Path(selector_name)
        selector.unlink()

        try:
            os.symlink(str(target), selector)
            os.replace(selector, self.current)
            _fsync_directory(self.directory)
        finally:
            if selector.exists() or selector.is_symlink():
                selector.unlink()

        loaded = self.load_current()
        if (loaded is None
                or loaded["checkpoint"] != checkpoint
                or loaded["trusted_subtrees"] != trusted_subtrees):
            raise ValueError("published RP state validation failed")

        return loaded
