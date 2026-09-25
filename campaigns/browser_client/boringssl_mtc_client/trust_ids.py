"""Read ID coordinates from existing local MCF1 config; not authentication."""


def configured_ids(raw, mode):
    if mode not in ('standalone', 'landmark'):
        raise ValueError('Unknown mode')
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(raw):
            raise ValueError('Truncated MCF1 config')
        result = raw[pos:pos+n]
        pos += n
        return result

    def number(n):
        return int.from_bytes(take(n), 'big')

    if take(4) != b'MCF1':
        raise ValueError('Expected MCF1 config')
    caid = take(number(1)).decode('ascii')
    parts = caid.split('.')
    if any(not p.isdecimal() or str(int(p)) != p or int(p) > 0xffffffff for p in parts):
        raise ValueError('Noncanonical CA ID')
    if number(1) != 2:
        raise ValueError('Expected two configured signers')
    for _ in range(2):
        take(number(1))
        take(number(2))
    log = number(2)
    take(16)  # min/max serial interval, verified by the native loader
    landmark = number(4) if mode == 'landmark' else None
    if not log or (mode == 'landmark' and not landmark):
        raise ValueError('Invalid ID coordinates')
    individual = f'{caid}.1.{log}.{landmark}' if landmark else caid
    group = f'{caid}.2.{log}.{landmark}' if landmark else caid
    return dict(caid=caid, log_number=log, landmark_number=landmark,
                selected_id=individual, requested_id=group)
