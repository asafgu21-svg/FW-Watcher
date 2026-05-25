"""
Shared utilities and abstract base class for all firewall parsers.
"""
import csv
import io
from abc import ABC, abstractmethod

ParseAddressResult = tuple[dict, list[str]]
ParsePolicyResult  = tuple[list, list[str]]


# ── string helpers ─────────────────────────────────────────────────────────────

def norm(s: str) -> str:
    return (s.lower().strip()
            .replace(" ", "").replace("/", "").replace("#", "")
            .replace(".", "").replace("-", ""))


def find_col(headers: list[str], *candidates) -> int:
    nh = [norm(h) for h in headers]
    for c in candidates:
        nc = norm(c)
        if nc in nh:
            return nh.index(nc)
    return -1


def cell(row: list[str], idx: int) -> str:
    if idx < 0 or idx >= len(row):
        return ""
    return row[idx].strip().strip('"')


def split_list(raw: str) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.replace(",", " ").split() if p.strip()]


# ── CSV helpers ────────────────────────────────────────────────────────────────

def detect_delim(content: str) -> str:
    sample = content[:4096]
    return ";" if sample.count(";") > sample.count(",") else ","


def read_csv(content: str) -> tuple[list[str], list[list[str]]]:
    """Return (header_row, data_rows), skipping blank leading rows."""
    delim = detect_delim(content)
    rows = list(csv.reader(io.StringIO(content), delimiter=delim))
    for i, row in enumerate(rows):
        if any(c.strip() for c in row):
            return row, rows[i + 1:]
    return [], []


# ── scoring helper ─────────────────────────────────────────────────────────────

def header_score(headers: list[str], required: list[str], bonus: list[str]) -> float:
    """
    Score 0.0–1.0 for how well `headers` match this vendor's expected columns.
    Required columns contribute 70 %, bonus columns contribute 30 %.
    """
    if not required:
        return 0.0
    nh = {norm(h) for h in headers}
    req = sum(1 for c in required if norm(c) in nh) / len(required)
    bon = (sum(1 for c in bonus if norm(c) in nh) / len(bonus) * 0.3) if bonus else 0.0
    return min(1.0, req * 0.7 + bon)


# ── abstract base ──────────────────────────────────────────────────────────────

class FirewallParser(ABC):
    VENDOR: str = "Unknown"

    def score_addresses(self, headers: list[str]) -> float:
        """Confidence (0–1) that this header row is our vendor's address export."""
        return 0.0

    def score_policies(self, headers: list[str]) -> float:
        """Confidence (0–1) that this header row is our vendor's policy export."""
        return 0.0

    @abstractmethod
    def parse_addresses(self, content: str) -> ParseAddressResult: ...

    @abstractmethod
    def parse_policies(self, content: str) -> ParsePolicyResult: ...
