"""
Palo Alto Networks (PAN-OS) CSV parser.

Expected address columns:  Name, Location, Type, Address, Description, Tags
  Type values: ip-netmask | ip-range | fqdn | address-group

Expected policy columns:   Name, Tags, Source Zone, Destination Zone,
                           Source Address, Destination Address, Application,
                           Service, Action, Status, Description
  Action values: allow | deny | drop | reset-client | reset-server
"""
from parsers.base import (
    FirewallParser, ParseAddressResult, ParsePolicyResult,
    find_col, cell, split_list, read_csv, header_score, norm,
)
from models import AddressObject, PolicyObject


class PaloAltoParser(FirewallParser):
    VENDOR = "Palo Alto"

    _ADDR_REQ   = ["Name", "Type", "Address"]
    _ADDR_BONUS = ["Location", "Description", "Tags"]
    _POL_REQ    = ["Source Zone", "Destination Zone", "Source Address",
                   "Destination Address", "Action"]
    _POL_BONUS  = ["Name", "Application", "Service", "Status", "Description"]

    def score_addresses(self, headers: list[str]) -> float:
        s = header_score(headers, self._ADDR_REQ, self._ADDR_BONUS)
        nh = {norm(h) for h in headers}
        # PAN-OS uniquely has "location" (vsys) and "tags"
        if "location" in nh or "tags" in nh:
            s = min(1.0, s + 0.2)
        # PAN-OS type values use hyphens: "ip-netmask"
        if "ipnetmask" in nh or "iprange" in nh:
            s = min(1.0, s + 0.15)
        return s

    def score_policies(self, headers: list[str]) -> float:
        s = header_score(headers, self._POL_REQ, self._POL_BONUS)
        nh = {norm(h) for h in headers}
        # PAN-OS uniquely has "application" and "url category"
        if "application" in nh:
            s = min(1.0, s + 0.2)
        if "sourcezone" in nh and "destinationzone" in nh:
            s = min(1.0, s + 0.15)
        return s

    # ── addresses ──────────────────────────────────────────────────────────────

    def parse_addresses(self, content: str) -> ParseAddressResult:
        addresses: dict = {}
        warnings: list[str] = []
        headers, data = read_csv(content)
        if not headers:
            return addresses, ["Empty file"]

        ci_name    = find_col(headers, "Name", "name")
        ci_type    = find_col(headers, "Type", "type", "Object Type")
        ci_addr    = find_col(headers, "Address", "address", "ip-netmask",
                               "ip-range", "fqdn", "IP/Netmask", "IP Netmask")
        ci_desc    = find_col(headers, "Description", "description", "Comment", "Comments")
        ci_tags    = find_col(headers, "Tags", "tags", "Tag")
        ci_members = find_col(headers, "Members", "members", "Addresses", "addresses")

        if ci_name < 0:
            ci_name = 0
            warnings.append("Could not find 'Name' column; assuming column 0.")

        for row in data:
            if not row or not any(c.strip() for c in row):
                continue
            name = cell(row, ci_name)
            if not name or name.startswith("#"):
                continue

            raw_type = cell(row, ci_type).lower().replace("-", "").replace("_", "") if ci_type >= 0 else "ipmask"
            if "group" in raw_type or "addressgroup" in raw_type:
                obj_type = "group"
            elif "range" in raw_type or "iprange" in raw_type:
                obj_type = "iprange"
            elif "fqdn" in raw_type:
                obj_type = "fqdn"
            else:
                obj_type = "ipmask"

            raw_addr = cell(row, ci_addr) if ci_addr >= 0 else ""
            subnet_str, start_ip, end_ip, fqdn_val = "", "", "", ""

            if obj_type == "fqdn":
                fqdn_val = raw_addr
            elif obj_type == "iprange" or "-" in raw_addr:
                parts = raw_addr.split("-", 1)
                if len(parts) == 2:
                    obj_type  = "iprange"
                    start_ip  = parts[0].strip()
                    end_ip    = parts[1].strip()
            else:
                # "10.0.0.0/24" → keep as CIDR for the model
                if "/" in raw_addr:
                    subnet_str = raw_addr  # CIDR form — model handles it
                else:
                    subnet_str = raw_addr  # IP-only or empty

            members: list[str] = []
            if obj_type == "group" and ci_members >= 0:
                members = split_list(cell(row, ci_members))

            addresses[name] = AddressObject(
                name=name,
                obj_type=obj_type,
                subnet_str=subnet_str,
                start_ip=start_ip,
                end_ip=end_ip,
                fqdn=fqdn_val,
                interface="any",
                comment=cell(row, ci_desc) if ci_desc >= 0 else "",
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

        ci_name    = find_col(headers, "Name", "Rule Name", "RuleName", "name")
        ci_srczone = find_col(headers, "Source Zone", "SourceZone", "From Zone", "From")
        ci_dstzone = find_col(headers, "Destination Zone", "DestinationZone", "To Zone", "To")
        ci_src     = find_col(headers, "Source Address", "SourceAddress", "Source",
                               "Source Addresses", "Src")
        ci_dst     = find_col(headers, "Destination Address", "DestinationAddress",
                               "Destination", "Destination Addresses", "Dst")
        ci_app     = find_col(headers, "Application", "application", "App")
        ci_svc     = find_col(headers, "Service", "service", "Services")
        ci_action  = find_col(headers, "Action", "action", "Security Action")
        ci_status  = find_col(headers, "Status", "status", "Enabled", "Enable",
                               "Rule State", "RuleState")
        ci_desc    = find_col(headers, "Description", "description", "Comment", "Comments")

        if ci_src < 0:
            warnings.append("Could not find Source Address column.")
        if ci_dst < 0:
            warnings.append("Could not find Destination Address column.")
        if ci_action < 0:
            warnings.append("Could not find Action column; defaulting to allow.")

        for i, row in enumerate(data):
            if not row or not any(c.strip() for c in row):
                continue
            name = cell(row, ci_name) if ci_name >= 0 else f"Rule {i + 1}"
            if not name or name.startswith("#"):
                continue

            raw_action = cell(row, ci_action).lower() if ci_action >= 0 else "allow"
            action = "DENY" if any(k in raw_action for k in ("deny", "drop", "reset", "block")) else "ACCEPT"

            raw_status = cell(row, ci_status).lower() if ci_status >= 0 else "enabled"
            status = "disable" if any(k in raw_status for k in ("disab", "false", "no", "0")) else "enable"

            # Services: combine app + service columns
            services = split_list(cell(row, ci_svc)) if ci_svc >= 0 else []
            if ci_app >= 0:
                apps = split_list(cell(row, ci_app))
                services = list(dict.fromkeys(services + apps))  # merge, dedupe

            policies.append(PolicyObject(
                policy_id=str(i + 1),
                name=name,
                src_intf=cell(row, ci_srczone) if ci_srczone >= 0 else "",
                dst_intf=cell(row, ci_dstzone) if ci_dstzone >= 0 else "",
                src_addrs=split_list(cell(row, ci_src)) if ci_src >= 0 else [],
                dst_addrs=split_list(cell(row, ci_dst)) if ci_dst >= 0 else [],
                services=services,
                action=action,
                status=status,
                nat="",
                comment=cell(row, ci_desc) if ci_desc >= 0 else "",
            ))

        if not policies:
            warnings.append("No policies parsed — check column names.")
        return policies, warnings
