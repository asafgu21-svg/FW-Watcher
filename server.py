"""
FW Watcher — Flask backend for the web-based graph UI.
Run: python server.py  → opens http://localhost:5789 in the default browser.
"""
import threading
import webbrowser
from pathlib import Path

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

    # Nodes: all subnets + all groups + anything named in policy connections
    all_names: set[str] = set(topology.get_subnets())
    for n, a in topology.addresses.items():
        if a.obj_type == "group" and a.members:
            all_names.add(n)
    for c in conns:
        all_names.add(c["src"])
        all_names.add(c["dst"])

    for name in all_names:
        addr = topology.addresses.get(name)
        virtual = name not in topology.addresses
        members = topology.get_group_members(name) if addr else []
        nodes.append({
            "id": name,
            "label": name,
            "cidr": addr.display_addr if addr else "",
            "virtual": virtual,
            "isGroup": bool(members),
            "memberCount": len(members),
            "comment": addr.comment if addr else "",
            "members": [
                {
                    "name": m.name,
                    "type": m.obj_type,
                    "address": m.display_addr,
                    "comment": m.comment,
                }
                for m in members
            ],
        })

    for c in conns:
        if c["all_disabled"]:
            action = "disabled"
        elif c["winning_action"] == "ACCEPT":
            action = "accept"
        else:
            action = "deny"

        edges.append({
            "id": f"{c['src']}__{c['dst']}",
            "source": c["src"],
            "target": c["dst"],
            "action": action,
            "count": c["count"],
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
