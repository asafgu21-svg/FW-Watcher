"""
FortiGate CSV parsers — flexible column detection for both address and policy exports.
"""
import csv
import io
from models import AddressObject, PolicyObject


def _norm(s: str) -> str:
    return s.lower().strip().replace(" ", "").replace("/", "").replace("#", "").replace(".", "").replace("-", "")


def _find(headers: list[str], *candidates) -> int:
    nh = [_norm(h) for h in headers]
    for c in candidates:
        nc = _norm(c)
        if nc in nh:
            return nh.index(nc)
    return -1


def _val(row: list[str], idx: int) -> str:
    if idx < 0 or idx >= len(row):
        return ""
    return row[idx].strip().strip('"')


def _addr_list(raw: str) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.replace(",", " ").split() if p.strip()]


def _detect_delim(content: str) -> str:
    sample = content[:4096]
    return ";" if sample.count(";") > sample.count(",") else ","


def _find_header_row(rows: list[list[str]]) -> int:
    for i, row in enumerate(rows):
        if any(c.strip() for c in row):
            return i
    return 0


# ---------------------------------------------------------------------------

def parse_addresses(content: str) -> tuple[dict[str, AddressObject], list[str]]:
    """
    Returns (addresses_dict, warnings_list).
    Handles ipmask, iprange, fqdn, group.
    """
    addresses: dict[str, AddressObject] = {}
    warnings: list[str] = []

    delim = _detect_delim(content)
    rows = list(csv.reader(io.StringIO(content), delimiter=delim))
    if not rows:
        return addresses, ["Empty file"]

    hi = _find_header_row(rows)
    headers = rows[hi]
    data = rows[hi + 1:]

    ci_name    = _find(headers, "Name", "name")
    ci_type    = _find(headers, "Type", "type", "Object Type", "ObjectType")
    ci_subnet  = _find(headers, "Subnet", "subnet", "Subnet / IP Range",
                       "SubnetIPRange", "Details", "IP Range", "Subnet/IPRange")
    ci_start   = _find(headers, "Start IP", "StartIP", "start-ip", "startip")
    ci_end     = _find(headers, "End IP", "EndIP", "end-ip", "endip")
    ci_fqdn    = _find(headers, "FQDN", "fqdn")
    ci_intf    = _find(headers, "Interface", "interface",
                       "Associated Interface", "AssociatedInterface")
    ci_comment = _find(headers, "Comment", "comment", "Comments")
    ci_members = _find(headers, "Members", "members", "Member", "Group Members",
                       "GroupMembers")

    if ci_name < 0:
        ci_name = 0
        warnings.append("Could not find 'Name' column; assuming column 0.")

    for row in data:
        if not row or not any(c.strip() for c in row):
            continue

        name = _val(row, ci_name)
        if not name or name.startswith("#"):
            continue

        raw_type = _val(row, ci_type).lower() if ci_type >= 0 else "ipmask"
        if "group" in raw_type:
            obj_type = "group"
        elif "range" in raw_type:
            obj_type = "iprange"
        elif "fqdn" in raw_type:
            obj_type = "fqdn"
        else:
            obj_type = "ipmask"

        subnet_str = _val(row, ci_subnet) if ci_subnet >= 0 else ""
        start_ip   = _val(row, ci_start)  if ci_start >= 0 else ""
        end_ip     = _val(row, ci_end)    if ci_end >= 0 else ""

        # Detect iprange from "a.b.c.d-e.f.g.h" in the subnet field
        if "-" in subnet_str and not start_ip and obj_type in ("ipmask", "iprange"):
            parts = subnet_str.split("-", 1)
            if len(parts) == 2:
                obj_type = "iprange"
                start_ip = parts[0].strip()
                end_ip   = parts[1].strip()

        # Group members — prefer dedicated Members column, fall back to subnet/details column
        members: list[str] = []
        if obj_type == "group":
            raw_members = (_val(row, ci_members) if ci_members >= 0 else "") or subnet_str
            members = [m.strip() for m in raw_members.replace(",", " ").split() if m.strip()]

        addresses[name] = AddressObject(
            name=name,
            obj_type=obj_type,
            subnet_str=subnet_str,
            start_ip=start_ip,
            end_ip=end_ip,
            fqdn=_val(row, ci_fqdn) if ci_fqdn >= 0 else "",
            interface=_val(row, ci_intf) if ci_intf >= 0 else "any",
            comment=_val(row, ci_comment) if ci_comment >= 0 else "",
            members=members,
        )

    if not addresses:
        warnings.append("No address objects parsed — check column names.")
    return addresses, warnings


# ---------------------------------------------------------------------------

def parse_policies(content: str) -> tuple[list[PolicyObject], list[str]]:
    """
    Returns (policies_list, warnings_list).
    """
    policies: list[PolicyObject] = []
    warnings: list[str] = []

    delim = _detect_delim(content)
    rows = list(csv.reader(io.StringIO(content), delimiter=delim))
    if not rows:
        return policies, ["Empty file"]

    hi = _find_header_row(rows)
    headers = rows[hi]
    data = rows[hi + 1:]

    ci_id      = _find(headers, "#", "Seq.#", "policyid", "Policy ID", "ID",
                        "PolicyID", "Seq#", "SeqNo")
    ci_name    = _find(headers, "Name", "name")
    ci_srcintf = _find(headers, "From", "Source Interface", "srcintf",
                        "Source Zone", "Incoming Interface", "FromInterface")
    ci_dstintf = _find(headers, "To", "Destination Interface", "dstintf",
                        "Destination Zone", "Outgoing Interface", "ToInterface")
    ci_src     = _find(headers, "Source", "Source Address", "srcaddr",
                        "Source Addresses", "Src Address", "SrcAddress")
    ci_dst     = _find(headers, "Destination", "Destination Address", "dstaddr",
                        "Destination Addresses", "Dst Address", "DstAddress")
    ci_svc     = _find(headers, "Service", "service", "Services")
    ci_action  = _find(headers, "Action", "action")
    ci_status  = _find(headers, "Status", "status", "Enable", "Enabled")
    ci_nat     = _find(headers, "NAT", "nat")
    ci_comment = _find(headers, "Comment", "comment", "Comments")

    if ci_src < 0:
        warnings.append("Could not find Source Address column.")
    if ci_dst < 0:
        warnings.append("Could not find Destination Address column.")
    if ci_action < 0:
        warnings.append("Could not find Action column; defaulting to ACCEPT.")

    for i, row in enumerate(data):
        if not row or not any(c.strip() for c in row):
            continue

        raw_id = _val(row, ci_id) if ci_id >= 0 else str(i + 1)
        if not raw_id or raw_id.startswith("#"):
            continue
        try:
            int(raw_id)  # skip non-numeric IDs (sub-headers etc.)
        except ValueError:
            continue

        action_raw = _val(row, ci_action).upper() if ci_action >= 0 else "ACCEPT"
        # Normalise FortiGate's "ACCEPT" vs "DENY" vs "DROP"
        if "DENY" in action_raw or "DROP" in action_raw or "REJECT" in action_raw:
            action = "DENY"
        else:
            action = "ACCEPT"

        policies.append(PolicyObject(
            policy_id=raw_id,
            name=_val(row, ci_name) if ci_name >= 0 else f"Policy {raw_id}",
            src_intf=_val(row, ci_srcintf) if ci_srcintf >= 0 else "",
            dst_intf=_val(row, ci_dstintf) if ci_dstintf >= 0 else "",
            src_addrs=_addr_list(_val(row, ci_src)) if ci_src >= 0 else [],
            dst_addrs=_addr_list(_val(row, ci_dst)) if ci_dst >= 0 else [],
            services=_addr_list(_val(row, ci_svc)) if ci_svc >= 0 else [],
            action=action,
            status=_val(row, ci_status) if ci_status >= 0 else "enable",
            nat=_val(row, ci_nat) if ci_nat >= 0 else "",
            comment=_val(row, ci_comment) if ci_comment >= 0 else "",
        ))

    if not policies:
        warnings.append("No policies parsed — check column names.")
    return policies, warnings
