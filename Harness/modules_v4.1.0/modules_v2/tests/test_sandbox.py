import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def test_profiles_well_formed():
    from sandbox_runner import PROFILES
    for name, p in PROFILES.items():
        assert "image" in p, f"{name}: image manquante"
        assert p.get("net") in ("none", "host", "bridge")
        if "tmpfs_exec" in p:
            assert isinstance(p["tmpfs_exec"], bool), f"{name}: not bool"

def test_security_hardening():
    from sandbox_runner import PROFILES, build_docker_args
    for name, p in PROFILES.items():
        args = build_docker_args(name, p)
        assert "--cap-drop" in args
        assert "--read-only" in args
        assert "--rm" in args
