"""Ensure success is persisted only after the final preservation check."""
import ast
from pathlib import Path

source=Path('campaigns/packet_loss_campaign/run.py').read_text()
tree=ast.parse(source)
execute=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='execute')

finalize=None
for node in ast.walk(execute):
    if not isinstance(node,ast.Try):
        continue
    for index,statement in enumerate(node.body):
        if isinstance(statement,ast.Assign):
            targets=[target for target in statement.targets if isinstance(target,ast.Subscript)]
            if targets and any(
                isinstance(target.slice,ast.Constant) and target.slice.value=='passed'
                for target in targets
            ):
                finalize=(node.body,index)

assert finalize is not None
body,index=finalize
assert index>0
previous=body[index-1]
assert isinstance(previous,ast.Expr)
assert isinstance(previous.value,ast.Call)
assert isinstance(previous.value.func,ast.Name)
assert previous.value.func.id=='hashes'
print('PASS final preservation check precedes successful status')
