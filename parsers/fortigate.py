"""
FortiGate CSV parser — migrated from the original parsers.py.

Expected address columns:  Name, Type, Subnet, Interface, Comment, Members
Expected policy columns:   #/Seq.#, Name, From, To, Source, Destination,
                           Service, Action, Status, NAT, Comment
"""
from parsers.base import (
    FirewallParser, ParseAddressResult, ParsePolicyResult,
    find_col, cell, split_list, read_csv, header_score, norm,
)
from models import AddressObject, PolicyObject


class FortiGateParser(FirewallParser):
    VENDOR = "FortiGate"

    _ADDR_REQ   = ["Name", "Type", "Subnet"]
    _ADDR_BONUS = ["Interface", "Comment", "Members"]
    _POL_REQ    = ["Source", "Destination", "Action"]
    _POL_BONUS  = ["Seq.#", "From", "To", "Service", "Status", "NAT"]

    def score_addresses(self, headers: list[str]) -> float:
        s = header_score(headers, self._ADDR_REQ, self._ADDR_BONUS)
        nh = {norm(h) for h in headers}
        # FortiGate uses "Interface" + "Subnet", not "Zone" + "Address"
        if "interface" in nh and ("subnet" in nh or "subnetiprange" in nh):
            s = min(1.0, s + 0.2)
        return s

    def score_policies(self, headers: list[str]) -> float:
        s = header_score(headers, self._POL_REQ, self._POL_BONUS)
        nh = {norm(h) for h in headers}
        # FortiGate uses "From"/"To" as interface columns, not "SourceZone"
        if "from" in nh or "srcintf" in nh:
            s = min(1.0, s + 0.15)
        if any("seq" in h for h in nh) or "#" in nh:
            s = min(1.0, s + 0.1)
        return s

    # ── addresses ──────────────────────────────────────────────────────────────

    def parse_addresses(self, content: str) -> ParseAddressResult:
        addresses: dict = {}
        warnings: list[str] = []
        headers, data = read_csv(content)
        if not headers:
            return addresses, ["Empty file"]

        ci_name    = find_col(headers, "Name", "name")
        ci_type    = find_col(headers, "Type", "type", "Object Type", "ObjectType")
        ci_subnet  = find_col(headers, "Subnet", "subnet", "Subnet / IP Range",
                               "SubnetIPRange", "Details", "IP Range", "Subnet/IPRange")
        ci_start   = find_col(headers, "Start IP", "StartIP", "start-ip", "startip")
        ci_end     = find_col(headers, "End IP",   "EndIP",   "end-ip",   "endip")
        ci_fqdn    = find_col(headers, "FQDN", "fqdn")
        ci_intf    = find_col(headers, "Interface", "interface",
                               "Associated Interface", "AssociatedInterface")
        ci_comment = find_col(headers, "Comment", "comment", "Comments")
        ci_members = find_col(headers, "Members", "members", "Member",
                               "Group Members", "GroupMembers")

        if ci_name < 0:
            ci_name = 0
            warnings.append("Could not find 'Name' column; assuming column 0.")

        for row in data:
            if not row or not any(c.strip() for c in row):
                continue
            name = cell(row, ci_name)
            if not name or name.startswith("#"):
                continue

            raw_type = cell(row, ci_type).lower() if ci_type >= 0 else "ipmask"
            if "group" in raw_type:
                obj_type = "group"
            elif "range" in raw_type:
                obj_type = "iprange"
            elif "fqdn" in raw_type:
                obj_type = "fqdn"
            else:
                obj_type = "ipmask"

            subnet_str = cell(row, ci_subnet) if ci_subnet >= 0 else ""
            start_ip   = cell(row, ci_start)  if ci_start >= 0 else ""
            end_ip     = cell(row, ci_end)    if ci_end >= 0 else ""

            # "1.2.3.4-5.6.7.8" in subnet column → treat as iprange
            if "-" in subnet_str and not start_ip and obj_type in ("ipmask", "iprange"):
                parts = subnet_str.split("-", 1)
                if len(parts) == 2:
                    obj_type = "iprange"
                    start_ip = parts[0].strip()
                    end_ip   = parts[1].strip()

            members: list[str] = []
            if obj_type == "group":
                raw_m = (cell(row, ci_members) if ci_members >= 0 else "") or subnet_str
                members = [m.strip() for m in raw_m.replace(",", " ").split() if m.strip()]

            addresses[name] = AddressObject(
                name=name,
                obj_type=obj_type,
                subnet_str=subnet_str,
                start_ip=start_ip,
                end_ip=end_ip,
                fqdn=cell(row, ci_fqdn)    if ci_fqdn    >= 0 else "",
                interface=cell(row, ci_intf) if ci_intf   >= 0 else "any",
                comment=cell(row, ci_comment) if ci_comment >= 0 else "",
                members=members,
            )

        if not addresses:
            warnings.append("No address objects parsed — check column names.")
        return addresses, warnings

    # ── policies ───────────────────────────────────────────────────────────────

    def parse_policies(self, content: str) -> ParsePolicyResult:
        policies: list = []
        warnings: list[str] = []
        headers, data = read_csv(content)
        if not headers:
            return policies, ["Empty file"]

        ci_id      = find_col(headers, "#", "Seq.#", "policyid", "Policy ID", "ID",
                               "PolicyID", "Seq#", "SeqNo")
        ci_name    = find_col(headers, "Name", "name")
        ci_srcintf = find_col(headers, "From", "Source Interface", "srcintf",
                               "Source Zone", "Incoming Interface")
        ci_dstintf = find_col(headers, "To", "Destination Interface", "dstintf",
                               "Destination Zone", "Outgoing Interface")
        ci_src     = find_col(headers, "Source", "Source Address", "srcaddr",
                               "Source Addresses", "Src Address")
        ci_dst     = find_col(headers, "Destination", "Destination Address", "dstaddr",
                               "Destination Addresses", "Dst Address")
        ci_svc     = find_col(headers, "Service", "service", "Services")
        ci_action  = find_col(headers, "Action", "action")
        ci_status  = find_col(headers, "Status", "status", "Enable", "Enabled")
        ci_nat     = find_col(headers, "NAT", "nat")
        ci_comment = find_col(headers, "Comment", "comment", "Comments")

        if ci_src < 0:
            warnings.append("Could not find Source Address column.")
        if ci_dst < 0:
            warnings.append("Could not find Destination Address column.")
        if ci_action < 0:
            warnings.append("Could not find Action column; defaulting to ACCEPT.")

        for i, row in enumerate(data):
            if not row or not any(c.strip() for c in row):
                continue
            raw_id = cell(row, ci_id) if ci_id >= 0 else str(i + 1)
            if not raw_id or raw_id.startswith("#"):
                continue
            try:
                int(raw_id)
            except ValueError:
                continue  # skip sub-header rows

            action_raw = cell(row, ci_action).upper() if ci_action >= 0 else "ACCEPT"
            action = "DENY" if any(k in action_raw for k in ("DENY", "DROP", "REJECT")) else "ACCEPT"

            policies.append(PolicyObject(
                policy_id=raw_id,
                name=cell(row, ci_name)     if ci_name    >= 0 else f"Policy {raw_id}",
                src_intf=cell(row, ci_srcintf) if ci_srcintf >= 0 else "",
                dst_intf=cell(row, ci_dstintf) if ci_dstintf >= 0 else "",
                src_addrs=split_list(cell(row, ci_src)) if ci_src    >= 0 else [],
                dst_addrs=split_list(cell(row, ci_dst)) if ci_dst    >= 0 else [],
                services =split_list(cell(row, ci_svc)) if ci_svc    >= 0 else [],
                action=action,
                status=cell(row, ci_status)  if ci_status  >= 0 else "enable",
                nat=cell(row, ci_nat)        if ci_nat     >= 0 else "",
                comment=cell(row, ci_comment) if ci_comment >= 0 else "",
            ))

        if not policies:
            warnings.append("No policies parsed — check column names.")
        return policies, warnings
