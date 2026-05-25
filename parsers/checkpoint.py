"""
Check Point SmartConsole CSV parser.

Expected address columns:  Name, IPv4 Address, Subnet Mask (or Mask Length),
                           Type, Comments
  Type values: Network | Host | Address Range | Group

Expected policy columns:   No., Rule Name, Source, Destination, Service,
                           VPN, Action, Track, Install On, Time, Comment
  Action values: Accept | Drop | Reject | UserAuth | ClientAuth
"""
import ipaddress
from parsers.base import (
    FirewallParser, ParseAddressResult, ParsePolicyResult,
    find_col, cell, split_list, read_csv, header_score, norm,
)
from models import AddressObject, PolicyObject


def _prefix_to_subnet(ip: str, prefix_or_mask: str) -> str:
    """Convert "192.168.1.0" + "24" or "255.255.255.0" to CIDR string."""
    try:
        # If it's a plain number, treat as prefix length
        plen = int(prefix_or_mask)
        net = ipaddress.IPv4Network(f"{ip}/{plen}", strict=False)
        return str(net)
    except ValueError:
        pass
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix_or_mask}", strict=False)
        return str(net)
    except Exception:
        return f"{ip} {prefix_or_mask}" if prefix_or_mask else ip


class CheckPointParser(FirewallParser):
    VENDOR = "Check Point"

    _ADDR_REQ   = ["Name", "IPv4 Address"]
    _ADDR_BONUS = ["Subnet Mask", "Mask Length", "Type", "Comments"]
    _POL_REQ    = ["Source", "Destination", "Action"]
    _POL_BONUS  = ["No.", "Rule Name", "Service", "Track", "Install On"]

    def score_addresses(self, headers: list[str]) -> float:
        s = header_score(headers, self._ADDR_REQ, self._ADDR_BONUS)
        nh = {norm(h) for h in headers}
        # Check Point uniquely uses "IPv4 Address" and "Mask Length"
        if "ipv4address" in nh:
            s = min(1.0, s + 0.3)
        if "masklength" in nh:
            s = min(1.0, s + 0.15)
        return s

    def score_policies(self, headers: list[str]) -> float:
        s = header_score(headers, self._POL_REQ, self._POL_BONUS)
        nh = {norm(h) for h in headers}
        # Check Point uniquely has "Install On" and "Track"
        if "installon" in nh:
            s = min(1.0, s + 0.25)
        if "track" in nh:
            s = min(1.0, s + 0.1)
        return s

    # ── addresses ──────────────────────────────────────────────────────────────

    def parse_addresses(self, content: str) -> ParseAddressResult:
        addresses: dict = {}
        warnings: list[str] = []
        headers, data = read_csv(content)
        if not headers:
            return addresses, ["Empty file"]

        ci_name   = find_col(headers, "Name", "name", "Object Name")
        ci_type   = find_col(headers, "Type", "type", "Object Type", "ObjectType")
        ci_ip     = find_col(headers, "IPv4 Address", "IPv4Address", "IP Address",
                              "IPAddress", "Address", "IP")
        ci_mask   = find_col(headers, "Subnet Mask", "SubnetMask", "Mask Length",
                              "MaskLength", "Prefix", "Prefix Length", "Mask")
        ci_start  = find_col(headers, "First IP", "FirstIP", "Start IP", "StartIP")
        ci_end    = find_col(headers, "Last IP",  "LastIP",  "End IP",   "EndIP")
        ci_comment= find_col(headers, "Comments", "Comment", "comment")
        ci_members= find_col(headers, "Members", "Group Members", "GroupMembers")

        if ci_name < 0:
            ci_name = 0
            warnings.append("Could not find 'Name' column; assuming column 0.")

        for row in data:
            if not row or not any(c.strip() for c in row):
                continue
            name = cell(row, ci_name)
            if not name or name.startswith("#"):
                continue

            raw_type = cell(row, ci_type).lower() if ci_type >= 0 else "network"
            if "group" in raw_type:
                obj_type = "group"
            elif "range" in raw_type:
                obj_type = "iprange"
            elif "host" in raw_type:
                obj_type = "ipmask"
            else:
                obj_type = "ipmask"

            raw_ip    = cell(row, ci_ip)    if ci_ip   >= 0 else ""
            raw_mask  = cell(row, ci_mask)  if ci_mask >= 0 else ""
            start_ip  = cell(row, ci_start) if ci_start >= 0 else ""
            end_ip    = cell(row, ci_end)   if ci_end  >= 0 else ""

            subnet_str = ""
            if obj_type == "iprange" or (start_ip and end_ip):
                obj_type = "iprange"
            elif raw_ip:
                subnet_str = _prefix_to_subnet(raw_ip, raw_mask) if raw_mask else raw_ip

            members: list[str] = []
            if obj_type == "group" and ci_members >= 0:
                members = split_list(cell(row, ci_members))

            addresses[name] = AddressObject(
                name=name,
                obj_type=obj_type,
                subnet_str=subnet_str,
                start_ip=start_ip,
                end_ip=end_ip,
                fqdn="",
                interface="any",
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

        ci_no     = find_col(headers, "No.", "No", "Rule No", "RuleNo",
                              "Rule Number", "#", "Seq")
        ci_name   = find_col(headers, "Rule Name", "RuleName", "Name", "name")
        ci_src    = find_col(headers, "Source", "source", "Source Address",
                              "Sources")
        ci_dst    = find_col(headers, "Destination", "destination",
                              "Destination Address", "Destinations")
        ci_svc    = find_col(headers, "Service", "service", "Services",
                              "Port", "Ports")
        ci_action = find_col(headers, "Action", "action")
        ci_track  = find_col(headers, "Track", "track", "Log", "Logging")
        ci_comment= find_col(headers, "Comment", "Comments", "comment", "Description")
        ci_status = find_col(headers, "Status", "status", "Enabled", "Enable",
                              "Disabled")

        if ci_src < 0:
            warnings.append("Could not find Source column.")
        if ci_dst < 0:
            warnings.append("Could not find Destination column.")
        if ci_action < 0:
            warnings.append("Could not find Action column; defaulting to Accept.")

        for i, row in enumerate(data):
            if not row or not any(c.strip() for c in row):
                continue

            raw_id = cell(row, ci_no) if ci_no >= 0 else str(i + 1)
            if not raw_id:
                raw_id = str(i + 1)
            if raw_id.startswith("#"):
                continue

            raw_action = cell(row, ci_action).lower() if ci_action >= 0 else "accept"
            action = "DENY" if any(k in raw_action for k in ("drop", "reject", "deny", "block")) else "ACCEPT"

            raw_status = cell(row, ci_status).lower() if ci_status >= 0 else "enabled"
            status = "disable" if any(k in raw_status for k in ("disab", "false", "no", "0")) else "enable"

            rule_name = cell(row, ci_name) if ci_name >= 0 else f"Rule {raw_id}"

            policies.append(PolicyObject(
                policy_id=raw_id,
                name=rule_name,
                src_intf="",
                dst_intf="",
                src_addrs=split_list(cell(row, ci_src)) if ci_src >= 0 else [],
                dst_addrs=split_list(cell(row, ci_dst)) if ci_dst >= 0 else [],
                services =split_list(cell(row, ci_svc)) if ci_svc >= 0 else [],
                action=action,
                status=status,
                nat="",
                comment=cell(row, ci_comment) if ci_comment >= 0 else "",
            ))

        if not policies:
            warnings.append("No policies parsed — check column names.")
        return policies, warnings
