import json, hashlib, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def test_safe_eval_basic():
    from orchestrator import safe_eval
    assert safe_eval("1 + 2", {}) == 3
    assert safe_eval("summary.get('a')", {"summary": {"a": 5}}) == 5

def test_safe_eval_security():
    from orchestrator import safe_eval
    assert safe_eval("().__class__", {}) is None
    assert safe_eval("__import__('os')", {}) is None
    assert safe_eval("[x for x in range(10)]", {}) is None

def test_safe_eval_dos():
    from orchestrator import safe_eval
    assert safe_eval("(" * 5000 + "1" + ")" * 5000, {}) is None

def test_hmac_roundtrip():
    from orchestrator import sign, verify
    key = b"x" * 32
    body = {"a": 1, "global_sha256": hashlib.sha256(b'{"a":1}').hexdigest()}
    sig = sign(body, key)
    assert verify({**body, "signature": sig}, key)

def test_module_exists():
    from orchestrator import module_exists
    assert module_exists([sys.executable, __file__])
    assert not module_exists([])
