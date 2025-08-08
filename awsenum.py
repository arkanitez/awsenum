"""
AWS Topology Enumerator – single‑file web app

What it does
------------
• Lets you enumerate AWS resources using your own credentials (env, shared profile, or paste into the UI).
• Works with **limited privileges** – anything that returns AccessDenied is skipped and reported as a warning.
• Builds an **interactive graph** of resources and **network connections** (security-group flows, routes, LB listeners/targets, etc.).
• Different colors: resource edges vs network/protocol edges. Click nodes/edges to see full AWS details.
• Cross‑platform (Windows/Linux/Mac). One Python file. No DB. No telemetry.
• **Built-in tests**: visit `/_selftest` for quick checks; `/_health` for a health probe.

Run it
------
1) Python 3.10+ recommended

   python -m venv .venv
   . .venv/bin/activate   # Windows: .venv\\Scripts\\activate
   pip install fastapi uvicorn boto3 jinja2

2) Start (local only):

   python app.py

   # or
   uvicorn app:app --host 127.0.0.1 --port 8000

3) Open http://127.0.0.1:8000 in your browser.

Security notes
--------------
• This is a local tool. It does NOT store your keys; they live in process memory only.
• Prefer environment/shared profile credentials. Pasting keys is for lab use.
• Graph shows *configuration* connections, not live flow logs.

Extend it
---------
• See SERVICE_TOGGLES and the enumerate_* functions – add more AWS services as needed.
• The bottleneck is AWS API I/O. We parallelise regions/services where safe. Tune WORKERS.
"""

import json
import os
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
# FIX: Removed CORSMiddleware as it's a security risk for this local application.
# The browser's Same-Origin Policy is sufficient.
# from fastapi.middleware.cors import CORSMiddleware

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
WORKERS = 16  # global thread-pool for API calls (tune for your box)
BOTO_CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=25, connect_timeout=10)
DEFAULT_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-east-1",
    "ca-central-1", "sa-east-1", "eu-north-1", "eu-south-1"
]

SERVICE_TOGGLES = {
    "ec2": True,          # VPC/Subnets/RT/NAT/IGW/SG/ENI/Instances/VPCE
    "elbv2": True,        # ALB/NLB + listeners + TGs + targets
    "lambda": True,       # Lambda + VPC config
    "eks": True,          # EKS cluster VPC wiring
    "rds": True,          # RDS instances & SG/Subnets
    "dynamodb": True,     # Tables (regional)
    "s3": True,           # Buckets (global listing)
}

# ------------------------------------------------------------
# Graph model (for Cytoscape)
# ------------------------------------------------------------
class Graph:
    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add_node(self, id_: str, label: str, type_: str, region: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        if not id_:
            return
        with self._lock:
            if id_ in self._nodes:
                # Merge details
                if details:
                    self._nodes[id_]["data"]["details"].update(details)
                return
            self._nodes[id_] = {
                "data": {
                    "id": id_,
                    "label": label,
                    "type": type_,
                    "region": region or "",
                    "details": details or {},
                }
            }

    def add_edge(self, id_: str, source: str, target: str, label: str, type_: str, connection_type: str, details: Optional[Dict[str, Any]] = None):
        if not id_ or not source or not target:
            return
        with self._lock:
            if id_ in self._edges:
                return
            self._edges[id_] = {
                "data": {
                    "id": id_,
                    "source": source,
                    "target": target,
                    "label": label,
                    "type": type_,              # e.g., sg-rule, route, listener, attach
                    "connectionType": connection_type,  # resource | network
                    "details": details or {},
                }
            }

    def elements(self) -> List[Dict[str, Any]]:
        # Cytoscape expects one list with nodes+edges
        return list(self._nodes.values()) + list(self._edges.values())

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def safe_call(fn, *args, **kwargs) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return fn(*args, **kwargs), None
    except (ClientError, EndpointConnectionError) as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', str(e))
        return None, f"{fn.__name__}: {code}"
    except Exception as e:
        return None, f"{fn.__name__}: {e}"


def mk_id(*parts: str) -> str:
    return ":".join([p for p in parts if p])


def range_to_str(from_port, to_port, proto) -> str:
    if from_port is None and to_port is None:
        return "all"
    if proto in ("-1", "all"):
        return "all"
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def classify_target_type(target: Any) -> str:
    """Classify EC2 route target identifier into a node type.

    >>> classify_target_type("igw-abc")
    'igw'
    >>> classify_target_type("nat-123")
    'natgw'
    >>> classify_target_type("tgw-xyz")
    'tgw'
    >>> classify_target_type("pcx-1")
    'pcx'
    >>> classify_target_type("eni-9")
    'eni'
    >>> classify_target_type("i-0123")
    'i'
    >>> classify_target_type("something-else")
    'target'
    """
    s = str(target)
    if s.startswith("igw-"):
        return "igw"
    if s.startswith("nat-"):
        return "natgw"
    if s.startswith("tgw-"):
        return "tgw"
    if s.startswith("pcx-"):
        return "pcx"
    if s.startswith("eni-"):
        return "eni"
    if s.startswith("i-"):
        return "i"
    return "target"

# FIX: Refactored SG rule processing into a helper to reduce duplication.
def _process_sg_permissions(permissions: List[Dict], sgid: str, direction: str, g: Graph, region: str):
    """Helper to process security group ingress or egress rules."""
    is_egress = direction == "egress"
    for perm in permissions:
        proto = perm.get('IpProtocol')
        fport = perm.get('FromPort')
        tport = perm.get('ToPort')
        prange = range_to_str(fport, tport, proto)

        # From/To CIDRs
        for r in perm.get('IpRanges', []):
            cidr = r.get('CidrIp')
            if cidr:
                cidr_node = mk_id("cidr", region, cidr)
                g.add_node(cidr_node, cidr, "cidr", region)
                source, target = (mk_id("sg", region, sgid), cidr_node) if is_egress else (cidr_node, mk_id("sg", region, sgid))
                edge_id = mk_id("edge", region, source, target, direction, prange, proto)
                g.add_edge(edge_id, source, target, f"{proto}:{prange}", "sg-rule", "network")

        # From/To other SGs
        for up in perm.get('UserIdGroupPairs', []):
            other_sgid = up.get('GroupId')
            if other_sgid:
                # Ensure the other SG node exists
                g.add_node(mk_id("sg", region, other_sgid), other_sgid, "security_group", region)
                source, target = (mk_id("sg", region, sgid), mk_id("sg", region, other_sgid)) if is_egress else (mk_id("sg", region, other_sgid), mk_id("sg", region, sgid))
                edge_id = mk_id("edge", region, source, target, direction, prange, proto)
                g.add_edge(edge_id, source, target, f"{proto}:{prange}", "sg-rule", "network")

# ------------------------------------------------------------
# Enumerators (per region)
# ------------------------------------------------------------
def enumerate_ec2(session, region: str, g: Graph, warnings: List[str]):
    ec2 = session.client('ec2', region_name=region, config=BOTO_CFG)

    # VPCs
    vpcs, err = safe_call(ec2.describe_vpcs)
    if err:
        warnings.append(f"[{region}] EC2 describe_vpcs: {err}")
        return
    for v in vpcs.get('Vpcs', []):
        vid = v.get('VpcId')
        g.add_node(mk_id("vpc", region, vid), vid, "vpc", region, details={"cidr": v.get('CidrBlock')})

    # Subnets
    subnets, err = safe_call(ec2.describe_subnets)
    if err:
        warnings.append(f"[{region}] EC2 describe_subnets: {err}")
        subnets = {"Subnets": []}
    for s in subnets.get('Subnets', []):
        sid = s['SubnetId']
        vid = s['VpcId']
        g.add_node(mk_id("subnet", region, sid), sid, "subnet", region, details={"cidr": s.get('CidrBlock'), "az": s.get('AvailabilityZone')})
        g.add_edge(mk_id("edge", region, sid, vid), mk_id("subnet", region, sid), mk_id("vpc", region, vid), "subnet-of", "attach", "resource")

    # Route tables + associations + routes
    rts, err = safe_call(ec2.describe_route_tables)
    if err:
        warnings.append(f"[{region}] EC2 describe_route_tables: {err}")
        rts = {"RouteTables": []}
    for rt in rts.get('RouteTables', []):
        rtid = rt['RouteTableId']
        vpcid = rt.get('VpcId')
        g.add_node(mk_id("rtb", region, rtid), rtid, "route_table", region)
        if vpcid:
            g.add_edge(mk_id("edge", region, rtid, vpcid), mk_id("rtb", region, rtid), mk_id("vpc", region, vpcid), "rtb-of", "attach", "resource")
        for assoc in rt.get('Associations', []) or []:
            if assoc.get('SubnetId'):
                sid = assoc['SubnetId']
                g.add_edge(mk_id("edge", region, sid, rtid), mk_id("subnet", region, sid), mk_id("rtb", region, rtid), "assoc", "assoc", "resource")
        for r in rt.get('Routes', []) or []:
            dst = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock') or r.get('DestinationPrefixListId')
            target = (r.get('GatewayId') or r.get('NatGatewayId') or r.get('TransitGatewayId') or r.get('VpcPeeringConnectionId') or r.get('InstanceId') or r.get('NetworkInterfaceId'))
            if dst and target:
                dstnode = mk_id("cidr", region, dst) if "pl-" not in str(dst) else mk_id("prefixlist", region, str(dst))
                g.add_node(dstnode, str(dst), "cidr" if dstnode.startswith("cidr:") else "prefix_list", region)
                # Ensure target node exists at least as a stub
                ttype = classify_target_type(target)
                g.add_node(mk_id(tt
