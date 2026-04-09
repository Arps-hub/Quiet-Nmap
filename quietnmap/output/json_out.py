"""JSON output formatter."""

from __future__ import annotations

import json
from pathlib import Path

from quietnmap.models import ScanSession


def to_json(session: ScanSession, pretty: bool = True) -> str:
    """Serialize scan session to JSON string."""
    data = session.to_dict()
    if pretty:
        return json.dumps(data, indent=2, default=str)
    return json.dumps(data, default=str)


def save_json(session: ScanSession, path: str | Path) -> Path:
    """Save scan results as JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(session), encoding="utf-8")
    return path
