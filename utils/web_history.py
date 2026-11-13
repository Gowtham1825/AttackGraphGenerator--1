"""Persistent history for scans launched from the local web dashboard."""

from datetime import datetime
import json
from pathlib import Path


HISTORY_PATH = Path("reports/web_scan_history.json")
MAX_HISTORY_ITEMS = 50


def load_scan_history() -> list[dict]:
    """Return saved web scans, newest first, without failing the dashboard."""
    if not HISTORY_PATH.exists():
        return []

    try:
        with HISTORY_PATH.open(encoding="utf-8") as history_file:
            history = json.load(history_file)
    except (OSError, json.JSONDecodeError):
        return []

    return history if isinstance(history, list) else []


def save_scan_history(scan: dict) -> None:
    """Save a completed web scan while retaining a bounded local history."""
    history = load_scan_history()
    entry = {"scanned_at": datetime.now().isoformat(timespec="seconds"), **scan}
    history.insert(0, entry)

    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("w", encoding="utf-8") as history_file:
        json.dump(history[:MAX_HISTORY_ITEMS], history_file, indent=2)
