"""Offline local log; unsigned internal state, not an MTC checkpoint wire format.

Uses prepare.py's log/NNNNNN.entry layout and checkpoint tree_size/hash fields.
Local POSIX filesystem only. Cooperating operations lock the directory. A crash
between entry creation and state publication leaves an inconsistency: reopening
fails rather than repairing history. State is not protected against coordinated
replacement/rollback of both entries and state; retain trusted states separately.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile

from core import root, inclusion, consistency, subtree_consistency, verify_consistency


class LocalLog:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(exist_ok=True)
        if self.directory.is_symlink():
            raise ValueError('Log directory must not be a symlink')
        with self._locked():
            if not list(self.directory.iterdir()):
                (self.directory/'log').mkdir()
                self._publish({'tree_size': 0, 'hash': root([]).hex()})
            self._read()

    @contextmanager
    def _locked(self):
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _check_state(state):
        if (not isinstance(state, dict) or set(state) != {'tree_size', 'hash'}
                or type(state['tree_size']) is not int
                or not 0 <= state['tree_size'] < 1 << 48
                or not isinstance(state['hash'], str) or len(state['hash']) != 64
                or any(c not in '0123456789abcdef' for c in state['hash'])):
            raise ValueError('Malformed log state')

    def _read(self):
        log = self.directory/'log'
        state_file = self.directory/'state.json'
        if (set(p.name for p in self.directory.iterdir()) != {'log', 'state.json'}
                or log.is_symlink() or not log.is_dir()
                or state_file.is_symlink() or not state_file.is_file()):
            raise ValueError('Incomplete or unexpected log layout')
        state = json.loads(state_file.read_text())
        self._check_state(state)
        files = list(log.iterdir())
        if len(files) != state['tree_size']:
            raise ValueError('Entry count differs from persisted state')
        entries = []
        for i in range(len(files)):
            path = log/f'{i:06d}.entry'
            if path.is_symlink() or not path.is_file():
                raise ValueError('Missing or invalid entry at index '+str(i))
            entries.append(path.read_bytes())
        if root(entries).hex() != state['hash']:
            raise ValueError('Persisted root mismatch: history changed')
        return entries, state

    def _publish(self, state):
        # Only metadata is replaced; an existing entry is never opened for write.
        with tempfile.NamedTemporaryFile(mode='w', dir=self.directory,
                                         prefix='.state-', delete=False) as out:
            json.dump(state, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(out.name, self.directory/'state.json')

    def state(self):
        with self._locked():
            return self._read()[1]

    def get_entry(self, index):
        with self._locked():
            entries, _ = self._read()
            if type(index) is not int or not 0 <= index < len(entries):
                raise IndexError('Entry index out of range')
            return entries[index]

    def inclusion_proof(self, index, size):
        with self._locked():
            entries, _ = self._read()
            if type(size) is not int or not 1 <= size <= len(entries):
                raise IndexError('Tree size out of range')
            if type(index) is not int or not 0 <= index < size:
                raise IndexError('Entry index out of range')
            entries = entries[:size]
            return {'index': index, 'tree_size': size, 'hash': root(entries).hex(),
                    'proof': [h.hex() for h in inclusion(entries, index)]}

    def consistency_proof(self, old, new):
        with self._locked():
            entries, _ = self._read()
            if type(old) is not int or type(new) is not int or not 0 <= old <= new <= len(entries):
                raise IndexError('Tree sizes out of range')
            entries = entries[:new]
            return {'old_size': old, 'new_size': new,
                    'old_hash': root(entries[:old]).hex(), 'new_hash': root(entries).hex(),
                    'proof': [h.hex() for h in consistency(entries, old)]}

    def subtree_proof(self, start, end, size):
        with self._locked():
            entries, _ = self._read()
            if type(size) is not int or not 0 <= size <= len(entries):
                raise IndexError('Tree size out of range')
            if (type(start) is not int or type(end) is not int
                    or not 0 <= start <= end <= size):
                raise IndexError('Subtree range out of range')
            entries = entries[:size]
            try:
                proof = subtree_consistency(entries, start, end)
            except ValueError as exc:
                raise IndexError('Invalid subtree range') from exc
            return {'start': start, 'end': end, 'tree_size': size,
                    'hash': root(entries[start:end]).hex(),
                    'proof': [h.hex() for h in proof]}

    def append(self, entry):
        if not isinstance(entry, bytes):
            raise TypeError('Entry must be encoded bytes')
        with self._locked():
            entries, state = self._read()
            if len(entries) == (1 << 48)-1:
                raise ValueError('Tree-size limit reached')
            with (self.directory/'log'/f'{len(entries):06d}.entry').open('xb') as out:
                out.write(entry)
                out.flush()
                os.fsync(out.fileno())
            entries.append(entry)
            state = {'tree_size': len(entries), 'hash': root(entries).hex()}
            self._publish(state)
            return state

    def prove_consistency(self, old_state):
        self._check_state(old_state)
        with self._locked():
            entries, current = self._read()
            path = consistency(entries, old_state['tree_size'])
            if not verify_consistency(old_state['tree_size'], current['tree_size'],
                                      bytes.fromhex(old_state['hash']),
                                      bytes.fromhex(current['hash']), path):
                raise ValueError('Saved state is not a prefix of this log')
            return current, path
