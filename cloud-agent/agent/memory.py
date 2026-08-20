import json
import os
from datetime import datetime, timezone

_MEMORY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "memory.json",
)
_MAX_STORED = 50
_MAX_SHOWN = 10


def load_memory() -> list[dict]:
    if not os.path.exists(_MEMORY_FILE):
        return []
    try:
        with open(_MEMORY_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_turn(question: str, answer: str) -> None:
    history = load_memory()
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "answer": answer,
    })
    history = history[-_MAX_STORED:]
    with open(_MEMORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def build_memory_context(history: list[dict]) -> str:
    if not history:
        return ""
    recent = history[-_MAX_SHOWN:]
    lines = ["## Previous session findings (most recent last)\n"]
    for entry in recent:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        lines.append(f"[{ts}] Q: {entry['question']}")
        lines.append(f"A: {entry['answer']}\n")
    return "\n".join(lines)
