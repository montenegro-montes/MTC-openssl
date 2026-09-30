"""Deterministic local persistence tests; temporary directories only."""
from pathlib import Path
import tempfile

from core import root, verify_consistency
from local_log import LocalLog


def rejected(operation):
    try:
        operation()
    except (ValueError, OSError):
        return
    raise AssertionError('Inconsistent history accepted')


entries = [bytes([i]) for i in range(16)]
with tempfile.TemporaryDirectory(prefix='mtc-local-log-test-') as temporary:
    directory = Path(temporary)/'evolution'
    log = LocalLog(directory)
    assert log.state() == {'tree_size': 0, 'hash': root([]).hex()}
    for value in entries[:8]:
        log.append(value)
    state8 = log.state()
    assert state8 == {'tree_size': 8, 'hash': root(entries[:8]).hex()}
    del log
    log = LocalLog(directory)
    assert log.state() == state8
    for value in entries[8:]:
        log.append(value)
    state16, proof = log.prove_consistency(state8)
    assert state16 == {'tree_size': 16, 'hash': root(entries).hex()}
    assert verify_consistency(8, 16, bytes.fromhex(state8['hash']),
                              bytes.fromhex(state16['hash']), proof)
    assert [p.read_bytes() for p in sorted((directory/'log').iterdir())] == entries
    del log
    assert LocalLog(directory).state() == state16
    incompatible = {'tree_size': 8, 'hash': root([b'changed']+entries[1:8]).hex()}
    rejected(lambda: LocalLog(directory).prove_consistency(incompatible))
    assert not verify_consistency(8, 16, bytes.fromhex(incompatible['hash']),
                                  bytes.fromhex(state16['hash']), proof)
    modified = [bytes([proof[0][0]^1])+proof[0][1:]]+proof[1:]
    assert not verify_consistency(8, 16, bytes.fromhex(state8['hash']),
                                  bytes.fromhex(state16['hash']), modified)
    print('PASS: empty -> N=8 -> reload -> N=16 -> reload; consistency 8 -> 16')

    for mutation in ['modify', 'remove', 'reorder', 'state', 'missing-state', 'extra-entry']:
        directory = Path(temporary)/mutation
        log = LocalLog(directory)
        for value in entries[:8]:
            log.append(value)
        first, second = directory/'log/000000.entry', directory/'log/000001.entry'
        if mutation == 'modify':
            first.write_bytes(b'changed')
        elif mutation == 'remove':
            (directory/'log/000007.entry').unlink()
        elif mutation == 'reorder':
            a, b = first.read_bytes(), second.read_bytes()
            first.write_bytes(b); second.write_bytes(a)
        elif mutation == 'state':
            (directory/'state.json').write_text('{}')
        elif mutation == 'missing-state':
            (directory/'state.json').unlink()
        else:
            (directory/'log/000008.entry').write_bytes(b'uncommitted')
        before = {str(p.relative_to(directory)): p.read_bytes()
                  for p in directory.rglob('*') if p.is_file()}
        rejected(lambda: LocalLog(directory))
        rejected(lambda: log.append(b'must not append'))
        after = {str(p.relative_to(directory)): p.read_bytes()
                 for p in directory.rglob('*') if p.is_file()}
        assert after == before  # Failure never repairs or rewrites history.
    print('PASS: tampering, missing/reordered entries, invalid state and incomplete append rejected')
print('Local persistent MTC log tests PASS; temporary data removed')
