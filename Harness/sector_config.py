#!/usr/bin/env python3
# HARNESS-VALIDATION v4.0.0 — sector_config.py
# Adapter : unifie sector_base (mes configs) + interface ingénieur (get_sector_modules, etc.)
# Permet à l'orchestrateur et post_exploit_enum d'utiliser une API unifiée.
import os
import sys
from pathlib import Path

# Re-export depuis sector_base (notre codebase)
try:
    import sector_base
    SECTOR = sector_base.get_sector()
    
    def get_hvt_keywords():
        return sector_base.get_hvt_keywords()
    
    def get_port_map():
        return sector_base.get_port_map()
    
    def get_safe_mode():
        return sector_base.get_safe_mode()
    
    def is_write_allowed():
        return sector_base.is_write_allowed()
    
    def sector_info():
        cfg = sector_base.get_sector_config()
        return {
            "sector": cfg["sector"],
            "safe_mode": cfg["safe_mode"],
            "regulations": list(cfg["regulations"]),
            "hvt_keywords_count": len(cfg["hvt_keywords"]),
            "port_map_entries": len(cfg["port_map"]),
            "harness_version": cfg["harness_version"],
        }
    
    def get_matrix_file():
        """Retourne le nom du fichier matrix sectoriel."""
        return f"matrix_{SECTOR}.json"
    
    def get_sector_modules():
        """Retourne la liste des noms de modules pour ce secteur.
        Vide = tous les modules universels + sectoriels du config."""
        return []
    
    SIMULATE = False

except ImportError:
    # Fallback si sector_base absent
    SECTOR = os.environ.get("SECTOR", "crypto")
    SIMULATE = False
    
    def get_hvt_keywords():
        return ("wallet", "signer", "key", "redis", "docker", "kubelet")
    
    def get_port_map():
        return {}
    
    def get_safe_mode():
        return "full"
    
    def is_write_allowed():
        return True
    
    def sector_info():
        return {"sector": SECTOR}
    
    def get_matrix_file():
        return f"matrix_{SECTOR}.json"
    
    def get_sector_modules():
        return []

# Secteurs valides
VALID_SECTORS = ("crypto", "ot", "banking", "health", "energy", "telecom", "buildings", "it")

if __name__ == "__main__":
    import json
    print(json.dumps(sector_info(), indent=2, default=str))
