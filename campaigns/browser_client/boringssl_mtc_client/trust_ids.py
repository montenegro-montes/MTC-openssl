"""Read ID coordinates from typed local config; not authentication."""

from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'src/mtc'))
from config_formats import decode_mca2, decode_mtb2


def configured_ids(raw, mode):
    if mode not in ('standalone', 'landmark'):
        raise ValueError('Unknown mode')
    if mode == 'standalone':
        authority = decode_mca2(raw)
        landmark = None
    else:
        bundle = decode_mtb2(raw)
        authority = bundle.authority
        landmark = bundle.signaling_landmark
    caid, log = authority.ca_id, authority.log_number
    if mode == 'landmark' and landmark is None:
        individual = group = caid
        return dict(caid=caid, log_number=log, landmark_number=None,
                    selected_id=individual, requested_id=group)
    individual = f'{caid}.1.{log}.{landmark}' if landmark else caid
    group = f'{caid}.2.{log}.{landmark}' if landmark else caid
    return dict(caid=caid, log_number=log, landmark_number=landmark,
                selected_id=individual, requested_id=group)
