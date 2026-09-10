"""Static guard that the failure wrapper targets the frozen driver statements."""
from pathlib import Path
paper=Path('campaigns/paper_campaign/measure.py').read_text();benchmark=Path('mtc/benchmark.py').read_text();wrapper=Path('campaigns/packet_loss_campaign/measure.py').read_text()
assert paper.count("source=Path('/opt/mtc/benchmark.py').read_text()") == 1
assert benchmark.count("timeout=20") == 1
assert benchmark.count("Handshake failed: '+scenario") == 1
assert "HANDSHAKE_TIMEOUT_SECONDS" in wrapper
assert "PAPER_DIR='/opt/paper'" in wrapper
assert "sys.path.insert(0,PAPER_DIR)" in wrapper
print('PASS frozen-driver hooks and fixed timeout guard')
