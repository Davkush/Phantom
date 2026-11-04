#!/usr/bin/env python3
# HARNESS-VALIDATION v3.0.0 — configuration sectorielle.
# Charge la config du secteur via SECTOR env var (crypto|ot|banking|health|energy).
"""
Architecture multi-sectorielle :
  Le moteur (orchestrateur, sandbox, rapport signé) est générique.
  Ce qui change par secteur : protocoles, HVT keywords, port maps, matrix.

Usage :
  export SECTOR=ot          # sélectionne le secteur
  python3 orchestrator.py   # charge automatiquement sectors/ot.py

Chaque fichier sectoriel définit :
  - HVT_KEYWORDS : processus haute valeur à détecter en post-exploit
  - PORT_MAP : mapping port → service sectoriel
  - AIR_GAP_INDICATORS : indicateurs de compromission IT/OT
  - MODULES : liste des modules protocoles spécifiques au secteur
  - MATRIX_OVERRIDE : expressions expected sectorielles
  - DOCKER_BASE_IMAGE : image Docker de base pour les modules protocoles
  - READ_ONLY_DEFAULT : si True, les modules écriture sont désactivés par défaut
"""
import importlib
import os
import sys
from pathlib import Path

SECTORS_DIR = Path(__file__).parent

# Secteurs supportés
SUPPORTED_SECTORS = ("crypto", "ot", "banking", "health", "energy")

def get_sector() -> str:
    """Retourne le secteur actif (env SECTOR, défaut crypto)."""
    s = os.environ.get("SECTOR", "crypto").lower()
    if s not in SUPPORTED_SECTORS:
        sys.exit(f"[FATAL] Secteur '{s}' non supporté. "
                 f"Choisir parmi : {', '.join(SUPPORTED_SECTORS)}")
    return s

def load_sector_config(sector: str | None = None) -> dict:
    """Charge dynamiquement la configuration sectorielle.
    Retourne un dict avec HVT_KEYWORDS, PORT_MAP, MODULES, etc.
    """
    s = sector or get_sector()
    mod_name = f"sectors.{s}"
    try:
        mod = importlib.import_module(mod_name)
    except ImportError as e:
        sys.exit(f"[FATAL] Config secteur '{s}' introuvable : {e}")
    return {
        "sector": s,
        "HVT_KEYWORDS": getattr(mod, "HVT_KEYWORDS", ()),
        "PORT_MAP": getattr(mod, "PORT_MAP", {}),
        "AIR_GAP_INDICATORS": getattr(mod, "AIR_GAP_INDICATORS", ()),
        "MODULES": getattr(mod, "MODULES", []),
        "MATRIX_OVERRIDE": getattr(mod, "MATRIX_OVERRIDE", {}),
        "DOCKER_BASE_IMAGE": getattr(mod, "DOCKER_BASE_IMAGE", "python:3.11-slim"),
        "READ_ONLY_DEFAULT": getattr(mod, "READ_ONLY_DEFAULT", False),
        "CRITICAL_RISK": getattr(mod, "CRITICAL_RISK", "financial"),
        "REGULATION": getattr(mod, "REGULATION", ""),
    }

# ─── Config par défaut (crypto) ───────────────────────────────
# Importée quand SECTOR n'est pas défini ou = crypto
