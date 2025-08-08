"""
Streamlit Network Architecture Diagrammer + Threat/Risk Overlay (Extended)

Quick start (Windows/Linux/macOS):
  1) python -m venv .venv && source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
  2) pip install streamlit streamlit-agraph networkx pydantic matplotlib
     # Optional (if available): pip install streamlit-react-flow
  3) streamlit run app.py

What’s new vs MVP
- Position persistence with lock/unlock + auto-layouts (spring/kamada/shell by zone)
- Richer rule engine (zone policies, admin/bastion paths, S3/PrivateLink hints, WAF checks, DB access hygiene), with MITRE ATT&CK & CIS tags
- (Experimental) ReactFlow editor if the optional component is installed
- Export to PNG/SVG and basic Draw.io (.drawio) export/import (subset)
- Groups by zone, quick-connect edges, and save/load continues to work
- NEW: Export PNG/SVG with risk callouts & a tactics/severity legend baked in
- NEW: On-canvas ATT&CK tactics legend mapped from current findings
"""

from __future__ import annotations

import io
import json
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

import streamlit as st
import networkx as nx
from streamlit_agraph import agraph, Node, Edge, Config

# Try to import experimental ReactFlow component if installed
try:
    from streamlit_react_flow import react_flow  # type: ignore
    HAS_RF = True
except Exception:
    HAS_RF = False

# ----------------------------
# Data Models & Constants
# ----------------------------

ZONES = ["Public", "DMZ", "Private", "Mgmt", "Cloud"]
CRITICALITY = ["Low", "Medium", "High", "Critical"]
DATA_CLASS = ["Public", "Internal", "Confidential", "Secret"]
NODE_TYPES = [
    "Internet", "User", "Firewall", "WAF", "LoadBalancer", "WebServer",
    "AppServer", "APIGateway", "Server", "Database", "Cache", "MessageBus",
    "Storage", "S3", "HSM", "SIEM", "IDS", "EDR", "KMS", "VPN", "Bastion"
]

ZONE_COLORS = {
    "Public": "#B3E5FC",
    "DMZ": "#FFE082",
    "Private": "#C8E6C9",
    "Mgmt": "#E1BEE7",
    "Cloud": "#CFD8DC",
}

SEV_COLORS = {
    "Critical": "#ff1744",
    "High": "#ff9100",
    "Medium": "#ffd600",
    "Low": "#64dd17",
}

UNENCRYPTED_PROTOCOLS = {"http", "telnet", "ftp", "smtp"}
ADMIN_PROTOCOLS = {"ssh", "rdp", "winrm"}
DB_TYPES = {"Database"}
STORAGE_TYPES = {"Storage", "S3"}
SEC_MON_TYPES = {"SIEM", "IDS", "EDR"}
FIREWALL_TYPES = {"Firewall", "WAF"}
WEB_TIER = {"WebServer", "APIGateway", "LoadBalancer", "WAF"}
APP_TIER = {"AppServer", "Server"}

# Technique→Tactic mapping for legend (subset covering techniques used here)
TECHNIQUE_TO_TACTIC = {
    "T1190": "Initial Access",               # Exploit Public-Facing App
    "T1133": "Initial Access",               # External Remote Services
    "T1040": "Credential Access",            # Network Sniffing
    "T1021": "Lateral Movement",             # Remote Services
    "T1530": "Collection",                   # Data from Cloud Storage Object
    "T1046": "Discovery",                    # Network Service Discovery
    "T1078": "Persistence / Priv. Esc.",     # Valid Accounts
    "TA0001": "Initial Access",              # Tactic code directly used
}


@dataclass
class NodeData:
    id: str
    label: str
    type: str = "Server"
    zone: str = "Private"
    criticality: str = "Medium"
    internet_exposed: bool = False
    admin_interface: bool = False
    data_classification: str = "Internal"
    mfa_required: bool = True
    encrypted_at_rest: bool = True
    # Positioning
    x: Optional[float] = None
    y: Optional[float] = None
    fixed: bool = False  # lock node position in vis.js


@dataclass
class EdgeData:
    id: str
    source: str
    target: str
    protocol: str = "https"
    port: str = "443"
    encrypted: bool = True
    through_firewall: bool = False
    description: str = ""


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    mitigation: str
    nodes: List[str]
    edges: List[str]
    mitre: List[str] = field(default_factory=list)
    cis: List[str] = field(default_factory=list)


# ----------------------------
# Session State Initialization
# ----------------------------

def init_state():
    st.session_state.setdefault("nodes", {})  # type: Dict[str, NodeData]
    st.session_state.setdefault("edges", {})  # type: Dict[str, EdgeData]
    st.session_state.setdefault("counter", 1)
    st.session_state.setdefault("show_overlay", True)
    st.session_state.setdefault("lock_positions", False)
    st.session_state.setdefault("layout_name", "spring")
    st.session_state.setdefault("export_overlay", True)
    st.session_state.setdefault("export_legend", True)


init_state()


# ----------------------------
# Utility Functions
# ----------------------------

def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def add_node(ntype: str):
    nid = new_id("n")
    label = f"{ntype} {st.session_state['counter']}"
    st.session_state["counter"] += 1
    st.session_state["nodes"][nid] = NodeData(
        id=nid,
        label=label,
        type=ntype,
        zone="DMZ" if ntype in ("WebServer", "WAF", "LoadBalancer") else ("Public" if ntype == "Internet" else "Private"),
        criticality="High" if ntype in ("Database", "HSM", "KMS") else "Medium",
        internet_exposed=ntype in ("Internet", "WAF", "LoadBalancer", "WebServer", "APIGateway"),
        admin_interface=ntype in ("Server", "WebServer", "AppServer", "Database"),
        data_classification="Confidential" if ntype in ("Database", "HSM", "KMS") else "Internal",
        mfa_required=True,
        encrypted_at_rest=ntype not in ("Database", "Storage", "S3"),
    )


def delete_node(node_id: str):
    if node_id in st.session_state["nodes"]:
        to_delete = [eid for eid, e in st.session_state["edges"].items() if e.source == node_id or e.target == node_id]
        for eid in to_delete:
            del st.session_state["edges"][eid]
        del st.session_state["nodes"][node_id]


def add_edge(src: str, dst: str, protocol: str, port: str, encrypted: bool, through_fw: bool, desc: str):
    eid = new_id("e")
    st.session_state["edges"][eid] = EdgeData(
        id=eid, source=src, target=dst, protocol=protocol.lower(), port=port, encrypted=encrypted,
        through_firewall=through_fw, description=desc or f"{protocol}/{port}"
    )


def delete_edge(edge_id: str):
    if edge_id in st.session_state["edges"]:
        del st.session_state["edges"][edge_id]


# ----------------------------
# Layouts & Position Persistence
# ----------------------------

def to_networkx(nodes: Dict[str, NodeData], edges: Dict[str, EdgeData]) -> nx.DiGraph:
    G = nx.DiGraph()
    for nid, n in nodes.items():
        G.add_node(nid, **asdict(n))
    for e in edges.values():
        G.add_edge(e.source, e.target, id=e.id, protocol=e.protocol, port=e.port, encrypted=e.encrypted)
    return G


def apply_layout(layout_name: str):
    G = to_networkx(st.session_state["nodes"], st.session_state["edges"])
    if layout_name == "spring":
        pos = nx.spring_layout(G, seed=42, k=0.9)
    elif layout_name == "kamada":
        pos = nx.kamada_kawai_layout(G)
    elif layout_name == "shell":
        # shell by zone
        shells = [[] for _ in ZONES]
        zone_index = {z: i for i, z in enumerate(ZONES)}
        for nid, n in st.session_state["nodes"].items():
            shells[zone_index.get(n.zone, 0)].append(nid)
        pos = nx.shell_layout(G, shells=[s for s in shells if s])
    else:
        pos = nx.random_layout(G, seed=42)

    for nid, (x, y) in pos.items():
        n = st.session_state["nodes"][nid]
        n.x = float(x * 1000)
        n.y = float(y * 1000)


# ----------------------------
# Risk Analysis Engine (Enriched)
# ----------------------------

def add_find(findings: List[Finding], severity: str, title: str, detail: str, mitigation: str, nodes: List[str], edges: List[str], mitre: List[str] = None, cis: List[str] = None):
    findings.append(Finding(
        id=new_id("F"), severity=severity, title=title, detail=detail, mitigation=mitigation,
        nodes=nodes, edges=edges, mitre=mitre or [], cis=cis or []
    ))


def analyze(nodes: Dict[str, NodeData], edges: Dict[str, EdgeData]) -> List[Finding]:
    findings: List[Finding] = []
    get = nodes.get

    has_secmon = any(n.type in SEC_MON_TYPES for n in nodes.values())
    has_bastion = any(n.type == "Bastion" for n in nodes.values())

    firewall_nodes = {nid for nid, n in nodes.items() if n.type in FIREWALL_TYPES}

    # -------- Edge-level checks --------
    for e in edges.values():
        s = get(e.source)
        t = get(e.target)
        if not s or not t:
            continue

        # Direct Internet to sensitive without FW
        if s.type == "Internet" and (t.type in DB_TYPES or t.zone in {"Private", "Mgmt"}) and not e.through_firewall:
            add_find(
                findings, "Critical", "Direct Internet access to sensitive asset",
                f"Internet connects directly to {t.type} '{t.label}' in zone {t.zone} without firewall mediation.",
                "Introduce a firewall/WAF, place asset behind DMZ/private subnet, restrict inbound strictly.",
                [t.id], [e.id],
                mitre=["T1190", "T1133"], cis=["1.3", "9.4"]
            )

        # WAF in front of public web
        if t.type in {"WebServer", "APIGateway"} and s.type in {"Internet", "LoadBalancer"} and t.internet_exposed and not e.through_firewall:
            add_find(
                findings, "High", "Public web/API path lacks WAF",
                f"Public path to '{t.label}' is not flagged as passing through WAF.",
                "Place WAF in front of public web/API endpoints; enable TLS termination and rulesets.",
                [t.id], [e.id], mitre=["T1190"], cis=["9.5", "13.10"]
            )

        # Cross-zone unencrypted
        if s.zone != t.zone and (not e.encrypted or e.protocol in UNENCRYPTED_PROTOCOLS):
            sev = "High" if t.data_classification in {"Confidential", "Secret"} else "Medium"
            add_find(
                findings, sev, "Cross-zone traffic without encryption",
                f"{s.label} → {t.label} uses {e.protocol.upper()}/{e.port} without encryption across zones ({s.zone}→{t.zone}).",
                "Enforce TLS/mTLS; use IPSec/VPN/PrivateLink for cross-zone or cloud edges.",
                [s.id, t.id], [e.id], mitre=["T1040"], cis=["13.6", "3.11"]
            )

        # Admin protocols near Public without FW/Bastion
        if e.protocol in ADMIN_PROTOCOLS and (s.zone == "Public" or t.zone == "Public") and not (e.through_firewall or has_bastion):
            add_find(
                findings, "High", "Admin protocol exposed near Public zone",
                f"{e.protocol.upper()} on {s.label}→{t.label} near Public zone without WAF/Firewall/Bastion.",
                "Disable public admin; use VPN/Zero Trust and a bastion with MFA and JIT access.",
                [s.id, t.id], [e.id], mitre=["T1133", "T1021"], cis=["6.5", "16.12"]
            )

        # S3/Storage public access without PrivateLink
        if t.type == "S3" and (s.type == "Internet" or s.zone == "Public"):
            add_find(
                findings, "High", "S3 reachable from Public path",
                f"Traffic to S3 '{t.label}' originates from Public zone; prefer VPC endpoints/PrivateLink.",
                "Use S3 VPC gateway or interface endpoints; block public access at bucket level; enforce IAM and network policies.",
                [t.id], [e.id], mitre=["T1530"], cis=["3.1", "3.14"]
            )

    # -------- Node-level checks --------
    # DB should be reachable only from app tier
    for nid, n in nodes.items():
        if n.type in DB_TYPES:
            inbound = [e for e in edges.values() if e.target == nid]
            bad = [e for e in inbound if nodes.get(e.source).type not in (APP_TIER | WEB_TIER)]
            if bad:
                add_find(
                    findings, "High", "Database reachable from non-app tiers",
                    f"DB '{n.label}' has inbound from: {', '.join(nodes[e.source].label for e in bad)}.",
                    "Restrict DB to app/service tier only; enforce security groups/ACLs and DB auth.",
                    [nid] + [e.source for e in bad], [e.id for e in bad], mitre=["T1190", "T1046"], cis=["9.1", "9.2"]
                )

        # Admin interface Internet-exposed
        if n.admin_interface and n.internet_exposed:
            add_find(
                findings, "High", "Admin interface Internet-exposed",
                f"Node '{n.label}' has admin interface and is Internet-exposed.",
                "Place behind VPN/Zero Trust; MFA, IP allowlists, JIT via PAM.",
                [nid], [], mitre=["T1133"], cis=["16.12", "4.6"]
            )

        # Sensitive data + no MFA
        if n.data_classification in {"Confidential", "Secret"} and not n.mfa_required:
            add_find(
                findings, "Medium", "Sensitive data without MFA",
                f"Node '{n.label}' holds {n.data_classification} data but MFA is not required.",
                "Enforce MFA for all privileged/user access paths; integrate with IAM/PAM.",
                [nid], [], mitre=["T1078"], cis=["6.3"]
            )

        # Encryption at rest disabled on sensitive
        if n.data_classification in {"Confidential", "Secret"} and not n.encrypted_at_rest:
            add_find(
                findings, "High", "No encryption at rest for sensitive data",
                f"Node '{n.label}' stores {n.data_classification} data without encryption at rest.",
                "Enable disk/database encryption or KMS/HSM-backed keys.",
                [nid], [], mitre=["T1530"], cis=["3.4"]
            )

    # Architectural checks
    if len(firewall_nodes) == 1 and len(nodes) > 6:
        fw_id = next(iter(firewall_nodes))
        add_find(
            findings, "Medium", "Single firewall potential SPOF",
            "Only one firewall/WAF present; potential single point of failure and policy choke point.",
            "Introduce HA pair and ensure failover; segment per zone.",
            [fw_id], [], mitre=[], cis=["11.1"]
        )

    if not has_secmon and nodes:
        add_find(
            findings, "Medium", "No security monitoring/telemetry nodes found",
            "No SIEM/IDS/EDR present in the diagram; detection and response coverage unclear.",
            "Add SIEM/log collection, IDS/IPS, EDR; centralize critical logs.",
            [], [], mitre=["TA0001"], cis=["8.2"]
        )

    return findings


# ----------------------------
# Build Visualization (vis.js)
# ----------------------------

def build_graph(nodes: Dict[str, NodeData], edges: Dict[str, EdgeData], findings: List[Finding], show_overlay: bool) -> Tuple[List[Node], List[Edge]]:
    node_objs: List[Node] = []
    edge_objs: List[Edge] = []

    risky_nodes: Dict[str, str] = {}
    risky_edges: Dict[str, str] = {}
    sev_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    for f in findings:
        for nid in f.nodes:
            if nid not in risky_nodes or sev_rank[f.severity] > sev_rank[risky_nodes[nid]]:
                risky_nodes[nid] = f.severity
        for eid in f.edges:
            if eid not in risky_edges or sev_rank[f.severity] > sev_rank[risky_edges[eid]]:
                risky_edges[eid] = f.severity

    for n in nodes.values():
        base_color = ZONE_COLORS.get(n.zone, "#CFD8DC")
        border_width = 3 if n.id in risky_nodes else 1
        border_color = SEV_COLORS.get(risky_nodes.get(n.id, ""), "#455A64")
        title = (
            f"Type: {n.type}
Zone: {n.zone}
Criticality: {n.criticality}
Data: {n.data_classification}
"
            f"Internet-exposed: {n.internet_exposed}
Admin: {n.admin_interface}
MFA: {n.mfa_required}
Enc@rest: {n.encrypted_at_rest}"
        )
        fixed = n.fixed or st.session_state["lock_positions"]
        node_kwargs = {}
        if n.x is not None and n.y is not None:
            node_kwargs.update({"x": n.x, "y": n.y, "fixed": {"x": fixed, "y": fixed}})
        else:
            node_kwargs.update({"fixed": fixed})

        node_objs.append(Node(
            id=n.id,
            label=n.label,
            title=title,
            shape="box",
            color={"background": base_color, "border": border_color, "highlight": {"border": border_color}},
            borderWidth=border_width,
            size=25,
            group=n.zone,
            **node_kwargs,
        ))

    for e in edges.values():
        color = "#90A4AE"
        width = 2
        dashes = False
        if e.id in risky_edges:
            sev = risky_edges[e.id]
            color = SEV_COLORS.get(sev, color)
            width = 4
            dashes = True
        label = f"{e.protocol.upper()}/{e.port}" + (" 🔒" if e.encrypted else "")
        if e.through_firewall:
            label += " | FW"
        if e.description:
            label += f"
{e.description}"
        edge_objs.append(Edge(
            source=e.source, target=e.target, label=label, smooth=True, arrows="to", color=color, width=width, dashes=dashes
        ))

    if show_overlay:
        for idx, f in enumerate(findings, start=1):
            target_id = f.nodes[0] if f.nodes else None
            if not target_id:
                continue
            warn_id = f"warn-{idx}"
            node_objs.append(Node(
                id=warn_id,
                label=f"{f.severity[0]}{idx}",
                title=f"{f.severity}: {f.title}
{f.detail}
Mitigation: {f.mitigation}
MITRE: {', '.join(f.mitre) if f.mitre else '-'}
CIS: {', '.join(f.cis) if f.cis else '-'}",
                shape="ellipse",
                color={"background": SEV_COLORS.get(f.severity, "#FF5252"), "border": "#263238"},
                size=12,
            ))
            edge_objs.append(Edge(
                source=warn_id, target=target_id, arrows="to", color=SEV_COLORS.get(f.severity, "#FF5252"), width=2, dashes=True
            ))

    return node_objs, edge_objs


# ----------------------------
# Persistence (Save/Load)
# ----------------------------

def save_diagram(filename: str):
    data = {
        "version": 2,
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "nodes": [asdict(n) for n in st.session_state["nodes"].values()],
        "edges": [asdict(e) for e in st.session_state["edges"].values()],
    }
    os.makedirs("diagrams", exist_ok=True)
    path = os.path.join("diagrams", filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path, json.dumps(data, indent=2)


def load_diagram(file_content: str):
    data = json.loads(file_content)
    nodes = {n["id"]: NodeData(**n) for n in data.get("nodes", [])}
    edges = {e["id"]: EdgeData(**e) for e in data.get("edges", [])}
    st.session_state["nodes"] = nodes
    st.session_state["edges"] = edges


# ----------------------------
# Draw.io (mxGraph) Export/Import (subset)
# ----------------------------

def export_drawio() -> bytes:
    root = ET.Element("mxfile")
    diag = ET.SubElement(root, "diagram", name="Network")
    model = ET.SubElement(diag, "mxGraphModel")
    root_tag = ET.SubElement(model, "root")

    # required base cells
    ET.SubElement(root_tag, "mxCell", id="0")
    ET.SubElement(root_tag, "mxCell", id="1", parent="0")

    # nodes
    for n in st.session_state["nodes"].values():
        nid = n.id
        v = ET.SubElement(root_tag, "mxCell", id=nid, value=n.label, vertex="1", parent="1")
        geo = ET.SubElement(v, "mxGeometry", as_="geometry")
        geo.set("x", str(n.x or 100))
        geo.set("y", str(n.y or 100))
        geo.set("width", "120")
        geo.set("height", "50")

    # edges
    for e in st.session_state["edges"].values():
        ce = ET.SubElement(root_tag, "mxCell", id=e.id, edge="1", source=e.source, target=e.target, parent="1", value=f"{e.protocol}/{e.port}")
        ET.SubElement(ce, "mxGeometry", as_="geometry")

    buf = io.BytesIO()
    ET.ElementTree(root).write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()


essential_types = {
    "firewall": "Firewall", "waf": "WAF", "db": "Database", "database": "Database",
    "web": "WebServer", "app": "AppServer", "user": "User", "internet": "Internet",
    "s3": "S3", "bastion": "Bastion", "vpn": "VPN"
}

def import_drawio(xml_content: str):
    tree = ET.fromstring(xml_content)
    # crude parse: find all mxCell with vertex=1 (nodes) and with edge=1 (edges)
    nodes: Dict[str, NodeData] = {}
    edges: Dict[str, EdgeData] = {}

    for cell in tree.iter():
        if cell.tag.endswith("mxCell") and cell.attrib.get("vertex") == "1":
            nid = cell.attrib.get("id") or new_id("n")
            label = cell.attrib.get("value") or "Node"
            # guess type by label token
            lower = label.lower()
            ntype = next((v for k, v in essential_types.items() if k in lower), "Server")
            # default zone by type
            zone = "DMZ" if ntype in ("WebServer", "WAF", "LoadBalancer") else ("Public" if ntype == "Internet" else "Private")
            x = y = None
            for g in cell:
                if g.tag.endswith("mxGeometry"):
                    x = float(g.attrib.get("x", 100))
                    y = float(g.attrib.get("y", 100))
            nodes[nid] = NodeData(id=nid, label=label, type=ntype, zone=zone, x=x, y=y)

    for cell in tree.iter():
        if cell.tag.endswith("mxCell") and cell.attrib.get("edge") == "1":
            eid = cell.attrib.get("id") or new_id("e")
            src = cell.attrib.get("source")
            dst = cell.attrib.get("target")
            lbl = cell.attrib.get("value", "")
            proto, port = ("https", "443")
            if "/" in lbl:
                parts = lbl.split("/")
                if len(parts) == 2:
                    proto, port = parts[0], parts[1]
            edges[eid] = EdgeData(id=eid, source=src, target=dst, protocol=proto, port=str(port))

    if nodes:
        st.session_state["nodes"].update(nodes)
    if edges:
        st.session_state["edges"].update(edges)


# ----------------------------
# Image Export (PNG/SVG via matplotlib) with Overlay & Legend
# ----------------------------

def _risk_maps(findings: List[Finding]) -> Tuple[Dict[str, str], Dict[str, str]]:
    sev_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    risky_nodes: Dict[str, str] = {}
    risky_edges: Dict[str, str] = {}
    for f in findings:
        for nid in f.nodes:
            if nid not in risky_nodes or sev_rank[f.severity] > sev_rank[risky_nodes[nid]]:
                risky_nodes[nid] = f.severity
        for eid in f.edges:
            if eid not in risky_edges or sev_rank[f.severity] > sev_rank[risky_edges[eid]]:
                risky_edges[eid] = f.severity
    return risky_nodes, risky_edges


def _tactic_summary(findings: List[Finding]) -> Dict[str, List[str]]:
    summary: Dict[str, List[str]] = {}
    for f in findings:
        for tid in f.mitre:
            tactic = TECHNIQUE_TO_TACTIC.get(tid, None)
            if not tactic and tid.startswith("TA"):
                # tactic code provided directly
                tactic = TECHNIQUE_TO_TACTIC.get(tid, "Unknown Tactic")
            if not tactic:
                tactic = "Other"
            summary.setdefault(tactic, [])
            if tid not in summary[tactic]:
                summary[tactic].append(tid)
    return summary


def export_image(fmt: str = "png", include_overlay: bool = True, include_legend: bool = True) -> bytes:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle

    nodes = st.session_state["nodes"]
    edges = st.session_state["edges"]
    findings = analyze(nodes, edges) if nodes else []
    risky_nodes, risky_edges = _risk_maps(findings)

    G = to_networkx(nodes, edges)

    # Position map
    pos = {nid: (n.x or 0.0, n.y or 0.0) for nid, n in nodes.items()}
    if any(p != (0.0, 0.0) for p in pos.values()):
        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        minx, maxx = min(xs), max(xs)
        miny, maxy = min(ys), max(ys)
        rngx = (maxx - minx) or 1.0
        rngy = (maxy - miny) or 1.0
        pos = {k: ((v[0]-minx)/rngx, (v[1]-miny)/rngy) for k, v in pos.items()}
    else:
        pos = nx.spring_layout(G, seed=42)

    fig = plt.figure(figsize=(12, 8))
    ax = plt.gca()
    ax.set_axis_off()

    # Node styling arrays
    node_ids = list(G.nodes)
    node_colors = [ZONE_COLORS.get(nodes[nid].zone, "#CFD8DC") for nid in node_ids]
    node_edgecolors = [SEV_COLORS.get(risky_nodes.get(nid, ""), "#455A64") for nid in node_ids]
    node_lw = [3 if nid in risky_nodes else 1 for nid in node_ids]

    # Draw base edges
    nx.draw_networkx_edges(G, pos, alpha=0.7, arrows=False, ax=ax)

    # Overlay risky edges with color + dashes
    if risky_edges:
        risky_e = [(u, v) for u, v, d in G.edges(data=True) if d.get('id') in risky_edges]
        nx.draw_networkx_edges(
            G, pos, edgelist=risky_e, ax=ax, width=3, style='dashed',
            edge_color=[SEV_COLORS.get(risky_edges.get(G[u][v]['id'], ''), '#ff1744') for u, v in risky_e], arrows=False
        )

    # Draw nodes
    nx.draw_networkx_nodes(
        G, pos, node_size=1200, node_color=node_colors, edgecolors=node_edgecolors, linewidths=node_lw, ax=ax, node_shape='s'
    )
    nx.draw_networkx_labels(G, pos, labels={nid: nodes[nid].label for nid in node_ids}, font_size=9, ax=ax)

    # Risk callouts
    if include_overlay and findings:
        for idx, f in enumerate(findings, start=1):
            if not f.nodes:
                continue
            target = f.nodes[0]
            if target not in pos:
                continue
            x, y = pos[target]
            dx, dy = 0.05, 0.06  # offset for marker
            mx, my = x + dx, y + dy
            ax.scatter([mx], [my], s=80, c=SEV_COLORS.get(f.severity, '#ff1744'), zorder=5)
            ax.annotate(
                f"{f.severity[0]}{idx}", xy=(mx, my), xytext=(mx+0.01, my+0.01), fontsize=8,
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec=SEV_COLORS.get(f.severity, '#ff1744'), lw=1),
                arrowprops=dict(arrowstyle="->", color=SEV_COLORS.get(f.severity, '#ff1744'), lw=1),
            )

    # Legend box (severity + tactics)
    if include_legend:
        tactics = _tactic_summary(findings)
        # Draw legend background
        ax.add_patch(Rectangle((1.02, 0.02), 0.28, 0.40, transform=ax.transAxes, facecolor='white', edgecolor='#90A4AE', lw=1))
        ax.text(1.03, 0.40, 'Legend', transform=ax.transAxes, fontsize=11, weight='bold')
        # Severity
        y = 0.37
        for sev in ["Critical", "High", "Medium", "Low"]:
            ax.scatter([1.04], [y], transform=ax.transAxes, c=SEV_COLORS.get(sev), s=60)
            ax.text(1.07, y-0.005, sev, transform=ax.transAxes, fontsize=9)
            y -= 0.05
        # Tactics summary (top 6)
        ax.text(1.03, y, 'ATT&CK Tactics', transform=ax.transAxes, fontsize=10, weight='bold')
        y -= 0.04
        items = sorted(tactics.items(), key=lambda kv: len(kv[1]), reverse=True)[:6]
        for tactic, tids in items:
            ax.text(1.03, y, f"• {tactic} ({len(tids)})", transform=ax.transAxes, fontsize=8)
            y -= 0.035
        if not items:
            ax.text(1.03, y, '• (none yet)', transform=ax.transAxes, fontsize=8)

    buf = io.BytesIO()
    fig.savefig(buf, format=fmt, bbox_inches="tight", dpi=200)
    import matplotlib.pyplot as plt
    plt.close(fig)
    return buf.getvalue()


# ----------------------------
# UI
# ----------------------------

st.set_page_config(page_title="Net Diagram + Risk Overlay (Extended)", layout="wide")

st.title("🧭 Network Architecture Diagrammer + Threat/Risk Overlay – Extended")
st.caption("Drag nodes, auto-layout, lock positions, richer rules, optional ReactFlow editor, export/import.")

with st.sidebar:
    st.header("Palette")
    cols = st.columns(4)
    palette = ["Internet", "User", "Firewall", "WAF", "LoadBalancer", "WebServer", "AppServer", "APIGateway", "Server", "Database", "Storage", "S3", "HSM", "SIEM", "IDS", "EDR", "VPN", "Bastion"]
    for i, ntype in enumerate(palette):
        if cols[i % 4].button(ntype, use_container_width=True):
            add_node(ntype)

    st.divider()
    st.subheader("Add Node")
    with st.form("add_node_form", clear_on_submit=True):
        ntype = st.selectbox("Type", NODE_TYPES, index=NODE_TYPES.index("Server"))
        label = st.text_input("Label (optional)")
        zone = st.selectbox("Zone", ZONES, index=ZONES.index("Private"))
        criticality = st.selectbox("Criticality", CRITICALITY, index=1)
        data_class = st.selectbox("Data classification", DATA_CLASS, index=1)
        internet_exposed = st.checkbox("Internet-exposed", value=False)
        admin_interface = st.checkbox("Admin interface present", value=False)
        mfa_required = st.checkbox("MFA required", value=True)
        encrypted_at_rest = st.checkbox("Encryption at rest", value=True)
        submitted = st.form_submit_button("Add node")
        if submitted:
            nid = new_id("n")
            st.session_state["nodes"][nid] = NodeData(
                id=nid,
                label=label or f"{ntype} {st.session_state['counter']}",
                type=ntype, zone=zone, criticality=criticality,
                internet_exposed=internet_exposed, admin_interface=admin_interface,
                data_classification=data_class, mfa_required=mfa_required,
                encrypted_at_rest=encrypted_at_rest
            )
            st.session_state["counter"] += 1
            st.success("Node added.")

    st.subheader("Add Edge (Quick Connect)")
    if st.session_state["nodes"]:
        node_opts = {f"{n.label} ({nid[:6]})": nid for nid, n in st.session_state["nodes"].items()}
        with st.form("add_edge_form", clear_on_submit=True):
            src_label = st.selectbox("Source", list(node_opts.keys()))
            dst_label = st.selectbox("Target", list(node_opts.keys()))
            protocol = st.text_input("Protocol", value="https")
            port = st.text_input("Port", value="443")
            encrypted = st.checkbox("Encrypted in transit", value=True)
            through_fw = st.checkbox("Traverses firewall/WAF", value=False)
            desc = st.text_input("Description (optional)")
            submitted_e = st.form_submit_button("Add edge")
            if submitted_e:
                if node_opts[src_label] == node_opts[dst_label]:
                    st.error("Source and target must differ.")
                else:
                    add_edge(node_opts[src_label], node_opts[dst_label], protocol, port, encrypted, through_fw, desc)
                    st.success("Edge added.")
    else:
        st.info("Add at least one node to create edges.")

    st.divider()
    st.subheader("Edit / Delete")
    if st.session_state["nodes"]:
        node_opts2 = {f"{n.label} ({nid[:6]})": nid for nid, n in st.session_state["nodes"].items()}
        sel_node_label = st.selectbox("Select node", ["-"] + list(node_opts2.keys()), index=0)
        if sel_node_label != "-":
            nid = node_opts2[sel_node_label]
            n = st.session_state["nodes"][nid]
            n.label = st.text_input("Label", value=n.label, key=f"edit_label_{nid}")
            n.zone = st.selectbox("Zone", ZONES, index=ZONES.index(n.zone), key=f"edit_zone_{nid}")
            n.criticality = st.selectbox("Criticality", CRITICALITY, index=CRITICALITY.index(n.criticality), key=f"edit_crit_{nid}")
            n.data_classification = st.selectbox("Data", DATA_CLASS, index=DATA_CLASS.index(n.data_classification), key=f"edit_data_{nid}")
            n.internet_exposed = st.checkbox("Internet-exposed", value=n.internet_exposed, key=f"edit_ie_{nid}")
            n.admin_interface = st.checkbox("Admin interface", value=n.admin_interface, key=f"edit_admin_{nid}")
            n.mfa_required = st.checkbox("MFA required", value=n.mfa_required, key=f"edit_mfa_{nid}")
            n.encrypted_at_rest = st.checkbox("Encryption at rest", value=n.encrypted_at_rest, key=f"edit_encrest_{nid}")
            # manual position edit
            c1, c2 = st.columns(2)
            n.x = c1.number_input("x", value=float(n.x or 0.0), key=f"edit_x_{nid}")
            n.y = c2.number_input("y", value=float(n.y or 0.0), key=f"edit_y_{nid}")
            n.fixed = st.checkbox("Lock this node", value=n.fixed, key=f"edit_fixed_{nid}")
            if st.button("Delete node", type="primary"):
                delete_node(nid)
                st.experimental_rerun()

    if st.session_state["edges"]:
        edge_opts = {f"{e.source[:6]}→{e.target[:6]} {e.protocol}/{e.port} ({eid[:6]})": eid for eid, e in st.session_state["edges"].items()}
        sel_edge_label = st.selectbox("Select edge", ["-"] + list(edge_opts.keys()), index=0)
        if sel_edge_label != "-":
            eid = edge_opts[sel_edge_label]
            e = st.session_state["edges"][eid]
            e.protocol = st.text_input("Protocol", value=e.protocol, key=f"edit_proto_{eid}")
            e.port = st.text_input("Port", value=e.port, key=f"edit_port_{eid}")
            e.encrypted = st.checkbox("Encrypted", value=e.encrypted, key=f"edit_enc_{eid}")
            e.through_firewall = st.checkbox("Through firewall/WAF", value=e.through_firewall, key=f"edit_fw_{eid}")
            e.description = st.text_input("Description", value=e.description, key=f"edit_desc_{eid}")
            if st.button("Delete edge", type="primary"):
                delete_edge(eid)
                st.experimental_rerun()

# Main layout
colL, colR = st.columns([3, 2], gap="large")

with colL:
    st.subheader("Diagram")
    st.session_state["lock_positions"] = st.toggle("Lock all positions", value=st.session_state["lock_positions"])  # persist

    # Auto-layouts
    st.write(":pushpin: Use auto-layouts to generate coordinates; lock to persist.")
    layout_choice = st.selectbox("Auto-layout", ["spring", "kamada", "shell", "random"], index=["spring","kamada","shell","random"].index(st.session_state["layout_name"]))
    if st.button("Apply layout"):
        st.session_state["layout_name"] = layout_choice
        apply_layout(layout_choice)

    findings = analyze(st.session_state["nodes"], st.session_state["edges"]) if st.session_state["nodes"] else []

    st.session_state["show_overlay"] = st.toggle("Show risk overlay on diagram", value=st.session_state["show_overlay"])  # persists

    nodes_viz, edges_viz = build_graph(
        st.session_state["nodes"], st.session_state["edges"], findings, st.session_state["show_overlay"]
    )

    cfg = Config(
        width=900,
        height=720,
        directed=True,
        physics=not st.session_state["lock_positions"],
        hierarchical=False,
    )
    agraph(nodes=nodes_viz, edges=edges_viz, config=cfg)

    st.divider()
    st.subheader("Legend / ATT&CK Tactics")
    # Severity legend (simple text chips)
    st.markdown("**Severity colors:** Critical (red) · High (orange) · Medium (yellow) · Low (green)")
    # Tactic summary table
    if findings:
        tactic_summary = _tactic_summary(findings)
        rows = [
            {"Tactic": k, "Techniques": ", ".join(v), "Count": len(v)}
            for k, v in sorted(tactic_summary.items(), key=lambda kv: len(kv[1]), reverse=True)
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No findings yet to map to ATT&CK tactics.")

    st.divider()
    st.subheader("Export / Import")
    c0, c1, c2, c3 = st.columns(4)
    with c0:
        st.session_state["export_overlay"] = st.checkbox("Overlay in export", value=st.session_state["export_overlay"])
        st.session_state["export_legend"] = st.checkbox("Legend in export", value=st.session_state["export_legend"])
    with c1:
        if st.button("Export PNG"):
            png = export_image("png", include_overlay=st.session_state["export_overlay"], include_legend=st.session_state["export_legend"])
            st.download_button("Download PNG", data=png, file_name="diagram.png", mime="image/png")
    with c2:
        if st.button("Export SVG"):
            svg = export_image("svg", include_overlay=st.session_state["export_overlay"], include_legend=st.session_state["export_legend"])
            st.download_button("Download SVG", data=svg, file_name="diagram.svg", mime="image/svg+xml")
    with c3:
        xml = export_drawio()
        st.download_button("Export Draw.io", data=xml, file_name="diagram.drawio", mime="application/xml")

    up = st.file_uploader("Import Draw.io", type=["drawio", "xml"], accept_multiple_files=False)
    if up is not None:
        import_drawio(up.read().decode("utf-8"))
        st.success("Draw.io imported (best-effort).")
        st.experimental_rerun()

with colR:
    st.subheader("Findings")
    if findings:
        for f in findings:
            with st.expander(f"{f.severity} · {f.title}"):
                st.write(f.detail)
                st.markdown(f"**Mitigation**: {f.mitigation}")
                if f.mitre:
                    st.caption("MITRE ATT&CK: " + ", ".join(f.mitre))
                if f.cis:
                    st.caption("CIS Controls: " + ", ".join(f.cis))
                if f.nodes:
                    names = ", ".join(st.session_state["nodes"][nid].label for nid in f.nodes if nid in st.session_state["nodes"]) or "-"
                    st.caption(f"Nodes: {names}")
                if f.edges:
                    st.caption(f"Edges: {', '.join(f.edges)}")
    else:
        st.info("No findings yet. Add nodes/edges and/or adjust properties.")

    st.divider()
    st.subheader("Save / Load")
    fname_default = f"diagram_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_name = st.text_input("Filename", value=fname_default)
    c1, c2 = st.columns([1,1])
    with c1:
        if st.button("💾 Save to ./diagrams", use_container_width=True):
            path, payload = save_diagram(save_name)
            st.success(f"Saved to {path}")
            st.download_button("Download JSON", data=payload, file_name=save_name, mime="application/json")
    with c2:
        up2 = st.file_uploader("Load JSON diagram", type=["json"], accept_multiple_files=False)
        if up2 is not None:
            load_diagram(up2.read().decode("utf-8"))
            st.success("Diagram loaded.")
            st.experimental_rerun()

st.divider()

# ------------- Experimental ReactFlow Editor -------------
st.subheader("Experimental: ReactFlow Editor (if installed)")
if HAS_RF:
    st.caption("Two-way sync of nodes/edges JSON with a basic ReactFlow canvas.")
    # Convert state to RF format
    rf_nodes = [
        {
            "id": nid,
            "data": {"label": n.label},
            "position": {"x": n.x or 0, "y": n.y or 0},
            "type": "default"
        }
        for nid, n in st.session_state["nodes"].items()
    ]
    rf_edges = [
        {"id": e.id, "source": e.source, "target": e.target, "label": f"{e.protocol}/{e.port}"}
        for e in st.session_state["edges"].values()
    ]

    changed = react_flow(nodes=rf_nodes, edges=rf_edges, fit_view=True, height=500)
    if changed:
        # Update positions and edges back into session
        new_nodes = changed.get("nodes", [])
        new_edges = changed.get("edges", [])
        for n in new_nodes:
            nid = n.get("id")
            if nid in st.session_state["nodes"]:
                st.session_state["nodes"][nid].x = float(n.get("position", {}).get("x", 0))
                st.session_state["nodes"][nid].y = float(n.get("position", {}).get("y", 0))
        # Rebuild edge set (simple sync)
        if new_edges is not None:
            current = {}
            for e in new_edges:
                eid = e.get("id") or new_id("e")
                src = e.get("source")
                dst = e.get("target")
                lbl = e.get("label", "https/443")
                proto, port = ("https", "443")
                if "/" in lbl:
                    parts = lbl.split("/")
                    if len(parts) == 2:
                        proto, port = parts[0], parts[1]
                current[eid] = EdgeData(id=eid, source=src, target=dst, protocol=proto, port=str(port))
            st.session_state["edges"] = current
    st.info("ReactFlow is optional. Install with: pip install streamlit-react-flow")
else:
    st.info("Install optional editor: pip install streamlit-react-flow (component availability may vary).")

st.caption("Note: Drag position capture in vis.js is limited; use Auto-layouts or the ReactFlow editor to persist coordinates. This app intentionally stays dependency-light and cross-platform.")
