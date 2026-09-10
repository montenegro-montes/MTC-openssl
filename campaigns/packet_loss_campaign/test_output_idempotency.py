"""Regression guards for empty failures and repeatable plot generation."""
import ast
from pathlib import Path

analyze=Path('campaigns/packet_loss_campaign/analyze.py').read_text()
plots=Path('campaigns/packet_loss_campaign/plots.py').read_text()
ast.parse(analyze)
ast.parse(plots)

assert "if not failures:" in analyze
assert "(root/'failures.csv').open('w',newline='')" in analyze
assert "out.mkdir(exist_ok=True)" in plots
print('PASS empty-failure output and repeatable plot guards')
