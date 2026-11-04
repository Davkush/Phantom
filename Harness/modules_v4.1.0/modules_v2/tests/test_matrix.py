import json, ast
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture(scope="module")
def matrix():
    return json.loads((ROOT / "matrix.json").read_text())

def test_matrix_valid(matrix):
    assert "targets" in matrix

def test_expected_parsable(matrix):
    for name, t in matrix["targets"].items():
        expr = t.get("expected", "")
        assert expr, f"{name}: expected vide"
        ast.parse(expr, mode='eval')
