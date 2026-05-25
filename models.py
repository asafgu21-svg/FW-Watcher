import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AddressObject:
    name: str
    obj_type: str = "ipmask"   # ipmask | iprange | fqdn | group
    subnet_str: str = ""       # "192.168.1.0 255.255.255.0" or "x.x.x.x/prefix"
    start_ip: str = ""
    end_ip: str = ""
    fqdn: str = ""
    interface: str = "any"
    comment: str = ""
    members: list = field(default_factory=list)

    @property
    def network(self) -> Optional[ipaddress.IPv4Network]:
        if not self.subnet_str:
            return None
        try:
            parts = self.subnet_str.split()
            if len(parts) == 2:
                return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
            return ipaddress.IPv4Network(self.subnet_str, strict=False)
        except Exception:
            return None

    @property
    def is_subnet(self) -> bool:
        net = self.network
        return net is not None and net.prefixlen < 32

    @property
    def display_addr(self) -> str:
        if self.obj_type == "iprange":
            return f"{self.start_ip} – {self.end_ip}"
        if self.obj_type == "fqdn":
            return self.fqdn
        if self.obj_type == "group":
            return f"Group ({len(self.members)} members)"
        net = self.network
        return str(net) if net else self.subnet_str

    def contains(self, other: "AddressObject") -> bool:
        my_net = self.network
        if not my_net or not self.is_subnet:
            return False
        if other.obj_type == "ipmask":
            other_net = other.network
            if other_net:
                try:
                    return other_net.subnet_of(my_net)
                except Exception:
                    return False
        if other.obj_type == "iprange":
            try:
                s = ipaddress.IPv4Address(other.start_ip)
                e = ipaddress.IPv4Address(other.end_ip)
                return s in my_net and e in my_net
            except Exception:
                return False
        return False


@dataclass
class PolicyObject:
    policy_id: str
    name: str
    src_intf: str = ""
    dst_intf: str = ""
    src_addrs: list = field(default_factory=list)
    dst_addrs: list = field(default_factory=list)
    services: list = field(default_factory=list)
    schedule: str = "always"
    action: str = "ACCEPT"
    status: str = "enable"
    nat: str = ""
    comment: str = ""

    @property
    def is_enabled(self) -> bool:
        return self.status.lower() in ("enable", "enabled", "1", "true", "yes")

    @property
    def is_accept(self) -> bool:
        return self.action.upper() in ("ACCEPT", "ALLOW", "PERMIT")

    @property
    def action_label(self) -> str:
        return "ACCEPT" if self.is_accept else "DENY"


class NetworkTopology:
    def __init__(self):
        self.addresses: dict[str, AddressObject] = {}
        self.policies: list[PolicyObject] = []
        self._subnets: Optional[list[str]] = None
        self._connections: Optional[list[dict]] = None

    def add_address(self, addr: AddressObject):
        self.addresses[addr.name] = addr
        self._subnets = None
        self._connections = None

    def add_policy(self, policy: PolicyObject):
        self.policies.append(policy)
        self._connections = None

    def clear(self):
        self.addresses.clear()
        self.policies.clear()
        self._subnets = None
        self._connections = None

    # ------------------------------------------------------------------ helpers

    def get_subnets(self) -> list[str]:
        if self._subnets is None:
            self._subnets = [
                n for n, a in self.addresses.items()
                if a.obj_type == "ipmask" and a.is_subnet
            ]
        return self._subnets

    def _resolve_leaves(self, names: list[str]) -> list[AddressObject]:
        result, visited = [], set()
        def _r(name):
            if name in visited:
                return
            visited.add(name)
            addr = self.addresses.get(name)
            if not addr:
                return
            if addr.obj_type == "group":
                for m in addr.members:
                    _r(m)
            else:
                result.append(addr)
        for n in names:
            _r(n)
        return result

    def _find_subnet_for(self, addr: AddressObject) -> Optional[str]:
        if addr.name in self.get_subnets():
            return addr.name
        candidates = []
        for sn in self.get_subnets():
            s = self.addresses[sn]
            if s.contains(addr):
                net = s.network
                if net:
                    candidates.append((net.prefixlen, sn))
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
        # fall back to interface
        if addr.interface and addr.interface != "any":
            return f"[{addr.interface}]"
        return None

    # ------------------------------------------------------------------ public

    def get_subnet_members(self, subnet_name: str) -> list[AddressObject]:
        subnet = self.addresses.get(subnet_name)
        if not subnet:
            return []
        result = []
        for name, addr in self.addresses.items():
            if name == subnet_name:
                continue
            if addr.obj_type == "group":
                continue
            if name in self.get_subnets():
                # only include if it's a child subnet (strictly contained)
                if subnet.contains(addr) and name != subnet_name:
                    result.append(addr)
                continue
            if subnet.contains(addr):
                result.append(addr)
        return result

    def get_connections(self) -> list[dict]:
        if self._connections is not None:
            return self._connections

        conn_map: dict[tuple, list[PolicyObject]] = {}

        for policy in self.policies:
            src_leaves = self._resolve_leaves(policy.src_addrs)
            dst_leaves = self._resolve_leaves(policy.dst_addrs)

            src_nodes, dst_nodes = set(), set()

            for addr in src_leaves:
                if addr.name.lower() in ("all", "any"):
                    src_nodes.add("__ANY__")
                else:
                    sn = self._find_subnet_for(addr)
                    src_nodes.add(sn if sn else "__ANY__")

            for addr in dst_leaves:
                if addr.name.lower() in ("all", "any"):
                    dst_nodes.add("__ANY__")
                else:
                    sn = self._find_subnet_for(addr)
                    dst_nodes.add(sn if sn else "__ANY__")

            for src in src_nodes:
                for dst in dst_nodes:
                    if src == dst:
                        continue
                    key = (src, dst)
                    conn_map.setdefault(key, []).append(policy)

        self._connections = []
        for (src, dst), pols in conn_map.items():
            self._connections.append({
                "src": src,
                "dst": dst,
                "policies": pols,
                "has_accept": any(p.is_accept and p.is_enabled for p in pols),
                "has_deny": any(not p.is_accept and p.is_enabled for p in pols),
                "all_disabled": all(not p.is_enabled for p in pols),
                "count": len(pols),
            })

        return self._connections
