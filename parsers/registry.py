"""
Vendor detection registry.

Calls score_addresses / score_policies on every registered parser and
routes to whichever scores highest.  Falls back to FortiGate if all
parsers score 0 (keeps backward compatibility).
"""
from parsers.base import FirewallParser, ParseAddressResult, ParsePolicyResult, read_csv
from parsers.fortigate import FortiGateParser
from parsers.palo_alto import PaloAltoParser
from parsers.cisco_asa import CiscoASAParser
from parsers.checkpoint import CheckPointParser
from models import AddressObject, PolicyObject

_PARSERS: list[FirewallParser] = [
    FortiGateParser(),
    PaloAltoParser(),
    CiscoASAParser(),
    CheckPointParser(),
]


def list_vendors() -> list[str]:
    return [p.VENDOR for p in _PARSERS]


def _detect(content: str, mode: str) -> FirewallParser:
    headers, _ = read_csv(content)
    if not headers:
        return _PARSERS[0]  # default to FortiGate
    fn = "score_addresses" if mode == "addr" else "score_policies"
    scores = [(getattr(p, fn)(headers), p) for p in _PARSERS]
    scores.sort(key=lambda x: x[0], reverse=True)
    best_score, best_parser = scores[0]
    return best_parser if best_score > 0 else _PARSERS[0]


def parse_addresses(content: str) -> tuple[dict[str, AddressObject], list[str]]:
    parser = _detect(content, "addr")
    addrs, warns = parser.parse_addresses(content)
    return addrs, [f"Detected vendor: {parser.VENDOR}"] + warns


def parse_policies(content: str) -> tuple[list[PolicyObject], list[str]]:
    parser = _detect(content, "pol")
    pols, warns = parser.parse_policies(content)
    return pols, [f"Detected vendor: {parser.VENDOR}"] + warns
