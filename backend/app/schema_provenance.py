"""Platform-independent hashing for the ordered release feature schema."""

import hashlib
from pathlib import Path


def schema_sha256(path: Path) -> str:
    content = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(content).hexdigest()
