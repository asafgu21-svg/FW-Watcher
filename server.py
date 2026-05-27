"""
FW Watcher — Flask backend for the web-based graph UI.
Run: python server.py  → opens http://localhost:5789 in the default browser.
"""
import threading
import webbrowser
from pathlib import Path

import networkx as nx
from flask import Flask, jsonify, request, send_from_directory

from models import NetworkTopology
from parsers import parse_addresses, parse_policies, list_vendors

# ── state ──────────────────────────────────────────────────────────────────────
topology = NetworkTopology()

# ── app ────────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="web")


# ── static ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("web", "index.html")


# ── helpers ────────────────────────────────────────────────────────────────────
def _pop_vendor(warns: list[str]) -> tuple[str, list[str]]:
    """Extract the 'Detected vendor: X' prefix injected by the registry."""
    if warns and warns[0].startswith("Detected vendor: "):
        return warns[0][len("Detected vendor: "):], warns[1:]
    return "Unknown", warns


# ── API ────────────────────────────────────────────────────────────────────────
@app.route("/api/upload/addresses", methods=["POST"])
def upload_addresses():
    content = request.data.decode("utf-8-sig", errors="replace")
    addrs, warns = parse_addresses(content)
    vendor, warns = _pop_vendor(warns)
    for a in addrs.values():
        topology.add_address(a)
    return jsonify({**_topology_json(), "warnings": warns, "vendor": vendor})


@app.route("/api/upload/policies", methods=["POST"])
def upload_policies():
    content = request.data.decode("utf-8-sig", errors="replace")
    pols, warns = parse_policies(content)
    vendor, warns = _pop_vendor(warns)
    for p in pols:
        topology.add_policy(p)
    return jsonify({**_topology_json(), "warnings": warns, "vendor": vendor})


@app.route("/api/topology")
def get_topology():
    return jsonify(_topology_json())


@app.route("/api/clear", methods=["POST"])
def clear():
    topology.clear()
    return jsonify({"nodes": [], "edges": [], "warnings": []})


@app.route("/api/vendors")
def get_vendors():
    return jsonify({"vendors": list_vendors()})


# ── serialiser ─────────────────────────────────────────────────────────────────
def _topology_json() -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []

    conns = topology.get_connections()

    # Only nodes that actually appear in policy connections
    all_names: set[str] = set()
    conn_count: dict[str, int] = {}
    for c in conns:
        all_names.add(c["src"])
        all_names.add(c["dst"])
        conn_count[c["src"]] = conn_count.get(c["src"], 0) + 1
        conn_count[c["dst"]] = conn_count.get(c["dst"], 0) + 1

    max_degree = max(conn_count.values(), default=1)

    _G = nx.Graph()
    for _n in all_names:
        _G.add_node(_n)
    for _c in conns:
        _G.add_edge(_c["src"], _c["dst"])
    _core = nx.core_number(_G) if _G.number_of_nodes() > 0 else {}
    _max_core = max(_core.values(), default=1)

    def _serialize_members(names: list[str], visited: set[str]) -> list[dict]:
        result = []
        for m in names:
            addr = topology.addresses.get(m)
            if not addr or m in visited:
                continue
            is_grp = addr.obj_type == "group"
            sub = _serialize_members(addr.members, visited | {m}) if is_grp else []
            result.append({
                "name": m,
                "type": addr.obj_type,
                "address": addr.display_addr,
                "comment": addr.comment,
                "isGroup": is_grp,
                "memberCount": len(sub),
                "members": sub,
            })
        return result

    for name in all_names:
        addr = topology.addresses.get(name)
        virtual = name not in topology.addresses
        if addr and addr.obj_type == "group":
            members = _serialize_members(addr.members, {name})
        else:
            members = []
        degree = conn_count.get(name, 0)
        if virtual:
            zone = "any"
        elif addr:
            zone = addr.zone
        else:
            zone = "other"
        nodes.append({
            "id": name,
            "label": name,
            "cidr": addr.display_addr if addr else "",
            "virtual": virtual,
            "isGroup": bool(members) or (addr is not None and addr.obj_type == "group"),
            "memberCount": len(members),
            "comment": addr.comment if addr else "",
            "members": members,
            "connectionCount": degree,
            "degreeCentrality": round(degree / max_degree, 3),
            "coreNumber": _core.get(name, 0),
            "coreNorm": round(_core.get(name, 0) / max(_max_core, 1), 3),
            "zone": zone,
        })

    for c in conns:
        if c["all_disabled"]:
            action = "disabled"
        elif c["winning_action"] == "ACCEPT":
            action = "accept"
        else:
            action = "deny"

        seen_svcs: set[str] = set()
        services: list[str] = []
        for p in c["policies"]:
            for s in p.services:
                if s and s.lower() not in ("any", "all") and s not in seen_svcs:
                    seen_svcs.add(s)
                    services.append(s)
        top = services[:3]
        svc_label = ", ".join(top) + (f" +{len(services) - 3}" if len(services) > 3 else "")

        edges.append({
            "id": f"{c['src']}__{c['dst']}",
            "source": c["src"],
            "target": c["dst"],
            "action": action,
            "count": c["count"],
            "services": services,
            "servicesLabel": svc_label,
            "policies": [
                {
                    "id": p.policy_id,
                    "name": p.name,
                    "srcIntf": p.src_intf,
                    "dstIntf": p.dst_intf,
                    "sources": p.src_addrs,
                    "destinations": p.dst_addrs,
                    "services": p.services,
                    "action": p.action_label,
                    "enabled": p.is_enabled,
                    "nat": p.nat or "",
                    "comment": p.comment or "",
                }
                for p in c["policies"]
            ],
        })

    return {"nodes": nodes, "edges": edges}


# ── launch ─────────────────────────────────────────────────────────────────────
def _open_browser():
    import time
    time.sleep(0.8)
    webbrowser.open("http://localhost:5789")


if __name__ == "__main__":
    threading.Thread(target=_open_browser, daemon=True).start()
    print("FW Watcher starting -> http://localhost:5789")
    app.run(host="127.0.0.1", port=5789, debug=False)
