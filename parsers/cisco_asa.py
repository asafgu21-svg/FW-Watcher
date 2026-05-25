"""
Cisco ASA CSV parser (ASDM-style export).

Expected address columns:  Name, IP Address, Subnet Mask, Description
  (also handles: Name, IP Address/Prefix, Description with CIDR notation)

Expected policy columns:   Line/No., Action, Protocol, Source, Source Mask,
                           Destination, Destination Mask, Service/Port, Description
  Action values: permit | deny
"""
import ipaddress
from parsers.base import (
    FirewallParser, ParseAddressResult, ParsePolicyResult,
    find_col, cell, split_list, read_csv, header_score, norm,
)
from models import AddressObject, PolicyObject


def _mask_to_cidr(ip: str, mask: str) -> str:
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(net)
    except Exception:
        return f"{ip} {mask}" if mask else ip


class CiscoASAParser(FirewallParser):
    VENDOR = "Cisco ASA"

    _ADDR_REQ   = ["Name", "IP Address"]
    _ADDR_BONUS = ["Subnet Mask", "Netmask", "Description"]
    _POL_REQ    = ["Action", "Protocol", "Source", "Destination"]
    _POL_BONUS  = ["Line", "ACL Name", "Interface", "Service", "Description"]

    def score_addresses(self, headers: list[str]) -> float:
        s = header_score(headers, self._ADDR_REQ, self._ADDR_BONUS)
        nh = {norm(h) for h in headers}
        # Cisco ASA uniquely has "IP Address" (with space) — not plain "Address"
        if "ipaddress" in nh:
            s = min(1.0, s + 0.25)
        if "subnetmask" in nh or "netmask" in nh:
            s = min(1.0, s + 0.1)
        return s

    def score_policies(self, headers: list[str]) -> float:
        s = header_score(headers, self._POL_REQ, self._POL_BONUS)
        nh = {norm(h) for h in headers}
        # Cisco ASA uses "permit"/"deny" in action column (not "accept"/"allow")
        # We can detect it from the "ACL Name" or "Interface" column being present
        if "aclname" in nh or "accesslist" in nh:
            s = min(1.0, s + 0.25)
        if "protocol" in nh and "action" in nh:
            s = min(1.0, s + 0.1)
        return s

    # ── addresses ──────────────────────────────────────────────────────────────

    def parse_addresses(self, content: str) -> ParseAddressResult:
        addresses: dict = {}
        warnings: list[str] = []
        headers, data = read_csv(content)
        if not headers:
            return addresses, ["Empty file"]

        ci_name = find_col(headers, "Name", "name", "Object Name", "ObjectName")
        ci_ip   = find_col(headers, "IP Address", "IPAddress", "IP", "Address",
                            "IP Address/Prefix", "Subnet")
        ci_mask = find_col(headers, "Subnet Mask", "SubnetMask", "Netmask",
                            "Mask", "Network Mask")
        ci_desc = find_col(headers, "Description", "description", "Comment", "Comments")

        if ci_name < 0:
            ci_name = 0
            warnings.append("Could not find 'Name' column; assuming column 0.")
        if ci_ip < 0:
            warnings.append("Could not find IP Address column.")

        for row in data:
            if not row or not any(c.strip() for c in row):
                continue
            name = cell(row, ci_name)
            if not name or name.startswith("#"):
                continue

            raw_ip   = cell(row, ci_ip)   if ci_ip   >= 0 else ""
            raw_mask = cell(row, ci_mask) if ci_mask >= 0 else ""

            obj_type, subnet_str, start_ip, end_ip = "ipmask", "", "", ""

            if "-" in raw_ip:
                # IP range: "192.168.1.1-192.168.1.10"
                parts = raw_ip.split("-", 1)
                obj_type = "iprange"
                start_ip = parts[0].strip()
                end_ip   = parts[1].strip()
            elif "/" in raw_ip:
                subnet_str = raw_ip  # CIDR notation already
            elif raw_ip and raw_mask:
                subnet_str = _mask_to_cidr(raw_ip, raw_mask)
            else:
                subnet_str = raw_ip

            addresses[name] = AddressObject(
                name=name,
                obj_type=obj_type,
                subnet_str=subnet_str,
                start_ip=start_ip,
                end_ip=end_ip,
                fqdn="",
                interface="any",
                comment=cell(row, ci_desc) if ci_desc >= 0 else "",
                members=[],
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

        ci_line   = find_col(headers, "Line", "No.", "No", "Seq", "#", "Number")
        ci_action = find_col(headers, "Action", "action", "Permission")
        ci_proto  = find_col(headers, "Protocol", "protocol", "Proto")
        ci_src    = find_col(headers, "Source", "Source Host/Network",
                              "SourceHost", "Src Host/Network", "Source Address")
        ci_dst    = find_col(headers, "Destination", "Destination Host/Network",
                              "DstHost", "Dst Host/Network", "Destination Address")
        ci_svc    = find_col(headers, "Service", "Service/Port", "Port",
                              "Destination Port", "Services")
        ci_intf   = find_col(headers, "Interface", "interface",
                              "ACL Name", "ACLName", "Incoming Interface")
        ci_desc   = find_col(headers, "Description", "description", "Remark", "Comment")

        if ci_action < 0:
            warnings.append("Could not find Action column; defaulting to permit.")
        if ci_src < 0:
            warnings.append("Could not find Source column.")
        if ci_dst < 0:
            warnings.append("Could not find Destination column.")

        for i, row in enumerate(data):
            if not row or not any(c.strip() for c in row):
                continue

            raw_id = cell(row, ci_line) if ci_line >= 0 else str(i + 1)
            if not raw_id:
                raw_id = str(i + 1)
            if raw_id.startswith("#") or raw_id.lower() in ("remark", "rem"):
                continue

            raw_action = cell(row, ci_action).lower() if ci_action >= 0 else "permit"
            action = "DENY" if any(k in raw_action for k in ("deny", "drop", "reject", "block")) else "ACCEPT"

            proto = cell(row, ci_proto) if ci_proto >= 0 else ""
            svc_raw = cell(row, ci_svc) if ci_svc >= 0 else ""
            services = split_list(svc_raw) or ([proto] if proto and proto.lower() != "ip" else [])

            intf = cell(row, ci_intf) if ci_intf >= 0 else ""

            policies.append(PolicyObject(
                policy_id=raw_id,
                name=f"ACL-{raw_id}",
                src_intf=intf,
                dst_intf="",
                src_addrs=split_list(cell(row, ci_src)) if ci_src >= 0 else [],
                dst_addrs=split_list(cell(row, ci_dst)) if ci_dst >= 0 else [],
                services=services,
                action=action,
                status="enable",
                nat="",
                comment=cell(row, ci_desc) if ci_desc >= 0 else "",
            ))

        if not policies:
            warnings.append("No policies parsed — check column names.")
        return policies, warnings
