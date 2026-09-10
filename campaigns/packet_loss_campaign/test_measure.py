"""Guard that the failure wrapper targets and can patch the frozen driver."""
import ast
from pathlib import Path

paper=Path('campaigns/paper_campaign/measure.py').read_text()
benchmark=Path('mtc/benchmark.py').read_text()
wrapper=Path('campaigns/packet_loss_campaign/measure.py').read_text()
assert paper.count("source=Path('/opt/mtc/benchmark.py').read_text()") == 1
assert benchmark.count("timeout=20") == 1
assert benchmark.count("Handshake failed: '+scenario") == 1
assert "HANDSHAKE_TIMEOUT_SECONDS" in wrapper
assert "PAPER_DIR='/opt/paper'" in wrapper
assert "sys.path.insert(0,PAPER_DIR)" in wrapper

tree=ast.parse(wrapper)
constants={}
for node in tree.body:
    if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant):
        constants.update((target.id,node.value.value) for target in node.targets if isinstance(target,ast.Name))
assert benchmark.count(constants['original_run'])==1
assert benchmark.count(constants['failure'])==1
patched=benchmark.replace(constants['original_run'],constants['run_replacement'],1)
patched=patched.replace(constants['failure'],constants['failure_replacement'],1)
compile(patched,'failure-aware-benchmark-test','exec')
print('PASS frozen-driver hooks, substitutions, and fixed timeout guard')
