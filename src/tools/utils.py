import textwrap, logging

_log = logging.getLogger(__name__)

def safe_truncate(s: str, limit: int = 16_000, note: str = " …[truncated]"):
    if len(s.encode()) <= limit:
        return s
    return s.encode()[: limit - len(note)].decode(errors="ignore") + note

def dedent_strip(s: str) -> str:
    return textwrap.dedent(s).strip()