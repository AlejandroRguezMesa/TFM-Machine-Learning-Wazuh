"""
Sink — adaptador que mapea (source, line) a su fichero correspondiente
y escribe atómicamente. Único punto que sabe rutas.
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Dict


# Mapping centralizado: cualquier código que emita logs usa estas claves.
# Si cambias rutas, cámbialo aquí + en ossec.conf (ossec_localfile_snippet.xml).
SOURCE_PATHS: Dict[str, Path] = {
    "paloalto":              Path("/var/log/lab/paloalto.log"),
    "vcenter":               Path("/var/log/lab/vcenter.log"),
    "office365":             Path("/var/log/lab/office365.log"),
    # SentinelOne usa los paths "oficiales" requeridos por la regla 300600+
    "sentinelone_threats":   Path("/var/log/sentinelone.json"),
    "sentinelone_activity":  Path("/var/log/sentinelone_activities.json"),
    "sentinelone_device":    Path("/var/log/sentinelone-device-control.json"),
}


def write(source: str, line: str) -> None:
    if source not in SOURCE_PATHS:
        raise KeyError(f"Fuente desconocida: {source}. "
                       f"Valid: {list(SOURCE_PATHS)}")
    path = SOURCE_PATHS[source]
    path.parent.mkdir(parents=True, exist_ok=True)
    # append + flush — Wazuh polling sigue tail desde el último offset
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")
        f.flush()
