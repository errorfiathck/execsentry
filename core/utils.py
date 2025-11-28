import logging
import re
import os
import uuid
from datetime import datetime

def setup_logging(verbose: bool=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        level=level
    )

import logging
log = logging.getLogger("ExecSentry")

def make_marker():
    """Generate a unique marker string used in safe probes."""
    return f"ABE_MARKER_{uuid.uuid4().hex[:12]}"

def sanitize_path(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

# simple helper to find suspicious substrings
SUSPICIOUS_CMD_PATTERNS = [
    r"\bsubprocess\.", r"\bos\.system\b", r"\beval\(", r"\bexec\(", r"\bPopen\(", r"\bLoadLibrary\b", r"\bctypes\.CDLL\b"
]
SUSPICIOUS_CMD_RE = re.compile("|".join(SUSPICIOUS_CMD_PATTERNS), re.IGNORECASE)
