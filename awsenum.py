"""
AWS Topology Enumerator – single‑file web app

What it does
------------
• Lets you enumerate AWS resources using your own credentials (env, shared profile, or paste into the UI).
• Works with **limited privileges** – anything that returns AccessDenied is skipped and reported as a warning.
• Builds an **interactive graph** of resources and **network connections** (security-group flows, routes, LB listeners/targets, etc.).
• Different colors: resource edges vs network/protocol edges. Click nodes/edges to see full AWS details.
• Cross‑platform (Windows/Linux/Mac). One Python file. No DB. No telemetry.
• **Built‑in tests**: visit `/_selftest` for quick checks; `/_health` for a health probe.

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
from fastapi.middleware.cors import CORSMiddleware

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
                g.add_node(mk_id(ttype, region, target), target, ttype, region)
                g.add_edge(mk_id("edge", region, rtid, target, str(dst)), mk_id("rtb", region, rtid), mk_id(ttype, region, target), f"route→{dst}", "route", "network", details={"destination": dst})

    # IGWs
    igws, err = safe_call(ec2.describe_internet_gateways)
    if err:
        warnings.append(f"[{region}] EC2 describe_internet_gateways: {err}")
        igws = {"InternetGateways": []}
    for igw in igws.get('InternetGateways', []):
        igwid = igw['InternetGatewayId']
        g.add_node(mk_id("igw", region, igwid), igwid, "igw", region)
        for att in igw.get('Attachments', []) or []:
            vpcid = att.get('VpcId')
            if vpcid:
                g.add_edge(mk_id("edge", region, igwid, vpcid), mk_id("igw", region, igwid), mk_id("vpc", region, vpcid), "attached", "attach", "resource")

    # NAT gateways
    ngws, err = safe_call(ec2.describe_nat_gateways)
    if err:
        warnings.append(f"[{region}] EC2 describe_nat_gateways: {err}")
        ngws = {"NatGateways": []}
    for nat in ngws.get('NatGateways', []):
        natid = nat['NatGatewayId']
        g.add_node(mk_id("natgw", region, natid), natid, "nat_gateway", region, details={"state": nat.get('State')})
        sn = (nat.get('SubnetId') or nat.get('SubnetIds', [None])[0])
        if sn:
            g.add_edge(mk_id("edge", region, natid, sn), mk_id("natgw", region, natid), mk_id("subnet", region, sn), "in-subnet", "attach", "resource")
        vpcid = nat.get('VpcId')
        if vpcid:
            g.add_edge(mk_id("edge", region, natid, vpcid), mk_id("natgw", region, natid), mk_id("vpc", region, vpcid), "in-vpc", "attach", "resource")

    # Security groups + rules
    sgs, err = safe_call(ec2.describe_security_groups)
    if err:
        warnings.append(f"[{region}] EC2 describe_security_groups: {err}")
        sgs = {"SecurityGroups": []}
    sg_index = {}
    for sg in sgs.get('SecurityGroups', []):
        sgid = sg['GroupId']
        sg_index[sgid] = True
        g.add_node(mk_id("sg", region, sgid), f"{sg.get('GroupName')} ({sgid})", "security_group", region, details={"desc": sg.get('Description'), "vpc": sg.get('VpcId')})
    # SG ingress
    for sg in sgs.get('SecurityGroups', []):
        sgid = sg['GroupId']
        for perm in sg.get('IpPermissions', []):
            proto = perm.get('IpProtocol')
            fport = perm.get('FromPort')
            tport = perm.get('ToPort')
            prange = range_to_str(fport, tport, proto)
            # From CIDRs
            for r in perm.get('IpRanges', []):
                cidr = r.get('CidrIp')
                if cidr:
                    cidn = mk_id("cidr", region, cidr)
                    g.add_node(cidn, cidr, "cidr", region)
                    g.add_edge(mk_id("edge", region, cidr, sgid, "ingress", str(prange), str(proto)), cidn, mk_id("sg", region, sgid), f"{proto}:{prange}", "sg-rule", "network")
            # From SGs
            for up in perm.get('UserIdGroupPairs', []):
                other = up.get('GroupId')
                if other:
                    g.add_node(mk_id("sg", region, other), other, "security_group", region)
                    g.add_edge(mk_id("edge", region, other, sgid, "ingress", str(prange), str(proto)), mk_id("sg", region, other), mk_id("sg", region, sgid), f"{proto}:{prange}", "sg-rule", "network")
    # SG egress
    for sg in sgs.get('SecurityGroups', []):
        sgid = sg['GroupId']
        for perm in sg.get('IpPermissionsEgress', []):
            proto = perm.get('IpProtocol')
            fport = perm.get('FromPort')
            tport = perm.get('ToPort')
            prange = range_to_str(fport, tport, proto)
            for r in perm.get('IpRanges', []):
                cidr = r.get('CidrIp')
                if cidr:
                    cidn = mk_id("cidr", region, cidr)
                    g.add_node(cidn, cidr, "cidr", region)
                    g.add_edge(mk_id("edge", region, sgid, cidr, "egress", str(prange), str(proto)), mk_id("sg", region, sgid), cidn, f"{proto}:{prange}", "sg-rule", "network")
            for up in perm.get('UserIdGroupPairs', []):
                other = up.get('GroupId')
                if other:
                    g.add_node(mk_id("sg", region, other), other, "security_group", region)
                    g.add_edge(mk_id("edge", region, sgid, other, "egress", str(prange), str(proto)), mk_id("sg", region, sgid), mk_id("sg", region, other), f"{proto}:{prange}", "sg-rule", "network")

    # ENIs
    enis, err = safe_call(ec2.describe_network_interfaces)
    if err:
        warnings.append(f"[{region}] EC2 describe_network_interfaces: {err}")
        enis = {"NetworkInterfaces": []}
    for eni in enis.get('NetworkInterfaces', []):
        enid = eni['NetworkInterfaceId']
        g.add_node(mk_id("eni", region, enid), enid, "eni", region, details={"private_ip": eni.get('PrivateIpAddress')})
        if eni.get('VpcId'):
            g.add_edge(mk_id("edge", region, enid, eni['VpcId']), mk_id("eni", region, enid), mk_id("vpc", region, eni['VpcId']), "in-vpc", "attach", "resource")
        if eni.get('SubnetId'):
            g.add_edge(mk_id("edge", region, enid, eni['SubnetId']), mk_id("eni", region, enid), mk_id("subnet", region, eni['SubnetId']), "in-subnet", "attach", "resource")
        for sgid in [x['GroupId'] for x in eni.get('Groups', [])]:
            g.add_edge(mk_id("edge", region, enid, sgid), mk_id("eni", region, enid), mk_id("sg", region, sgid), "has-sg", "attach", "resource")
        if eni.get('Attachment') and eni['Attachment'].get('InstanceId'):
            iid = eni['Attachment']['InstanceId']
            g.add_node(mk_id("i", region, iid), iid, "instance", region)
            g.add_edge(mk_id("edge", region, iid, enid), mk_id("i", region, iid), mk_id("eni", region, enid), "eni", "attach", "resource")

    # Instances
    paginator = ec2.get_paginator('describe_instances')
    try:
        for page in paginator.paginate():
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    iid = inst['InstanceId']
                    name = next((t['Value'] for t in inst.get('Tags', []) if t.get('Key') == 'Name'), iid)
                    g.add_node(mk_id("i", region, iid), name, "instance", region, details={"state": inst.get('State', {}).get('Name')})
                    if inst.get('SubnetId'):
                        g.add_edge(mk_id("edge", region, iid, inst['SubnetId']), mk_id("i", region, iid), mk_id("subnet", region, inst['SubnetId']), "in-subnet", "attach", "resource")
                    for sg in inst.get('SecurityGroups', []) or []:
                        g.add_edge(mk_id("edge", region, iid, sg['GroupId']), mk_id("i", region, iid), mk_id("sg", region, sg['GroupId']), "has-sg", "attach", "resource")
    except ClientError as e:
        warnings.append(f"[{region}] EC2 describe_instances: {e.response['Error'].get('Code')}")

    # VPC Endpoints
    vpces, err = safe_call(ec2.describe_vpc_endpoints)
    if err:
        warnings.append(f"[{region}] EC2 describe_vpc_endpoints: {err}")
        vpces = {"VpcEndpoints": []}
    for vpce in vpces.get('VpcEndpoints', []):
        vid = vpce['VpcEndpointId']
        svc = vpce.get('ServiceName')
        g.add_node(mk_id("vpce", region, vid), vid, "vpc_endpoint", region, details={"service": svc, "type": vpce.get('VpcEndpointType')})
        g.add_node(mk_id("service", region, svc), svc, "aws_service", region)
        g.add_edge(mk_id("edge", region, vid, svc), mk_id("vpce", region, vid), mk_id("service", region, svc), "to-service", "bind", "resource")
        for sid in vpce.get('SubnetIds', []) or []:
            g.add_edge(mk_id("edge", region, vid, sid), mk_id("vpce", region, vid), mk_id("subnet", region, sid), "in-subnet", "attach", "resource")
        for rtbid in vpce.get('RouteTableIds', []) or []:
            g.add_edge(mk_id("edge", region, vid, rtbid), mk_id("vpce", region, vid), mk_id("rtb", region, rtbid), "rtb", "attach", "resource")


def enumerate_elbv2(session, region: str, g: Graph, warnings: List[str]):
    elb = session.client('elbv2', region_name=region, config=BOTO_CFG)
    ec2 = session.client('ec2', region_name=region, config=BOTO_CFG)

    lbs, err = safe_call(elb.describe_load_balancers)
    if err:
        warnings.append(f"[{region}] ELBv2 describe_load_balancers: {err}")
        return
    for lb in lbs.get('LoadBalancers', []) or []:
        lbarn = lb['LoadBalancerArn']
        name = lb['LoadBalancerName']
        scheme = lb.get('Scheme')
        lbtype = lb.get('Type')  # application | network | gateway
        g.add_node(mk_id("lb", region, lbarn), f"{name} ({lbtype})", "load_balancer", region, details={"scheme": scheme, "dns": lb.get('DNSName')})
        for sid in lb.get('AvailabilityZones', []):
            if sid.get('SubnetId'):
                g.add_edge(mk_id("edge", region, name, sid['SubnetId']), mk_id("lb", region, lbarn), mk_id("subnet", region, sid['SubnetId']), "in-subnet", "attach", "resource")
        for sgid in lb.get('SecurityGroups', []) or []:
            g.add_edge(mk_id("edge", region, name, sgid), mk_id("lb", region, lbarn), mk_id("sg", region, sgid), "has-sg", "attach", "resource")

        # Listeners → (Internet/internal) to LB edges
        listeners, err = safe_call(elb.describe_listeners, LoadBalancerArn=lbarn)
        if err:
            warnings.append(f"[{region}] ELBv2 describe_listeners ({name}): {err}")
            listeners = {"Listeners": []}
        for lst in listeners.get('Listeners', []):
            proto = lst.get('Protocol')
            port = lst.get('Port')
            # Represent external clients depending on scheme
            ext_id = mk_id("internet", region, "0.0.0.0/0") if scheme == "internet-facing" else mk_id("vpc", region, lb.get('VpcId'))
            g.add_node(ext_id, "Internet" if scheme == "internet-facing" else f"VPC {lb.get('VpcId')}", "external", region)
            g.add_edge(mk_id("edge", region, lbarn, str(port), str(proto)), ext_id, mk_id("lb", region, lbarn), f"{proto}:{port}", "listener", "network")

        # TargetGroups
        tgs, err = safe_call(elb.describe_target_groups, LoadBalancerArn=lbarn)
        if err:
            warnings.append(f"[{region}] ELBv2 describe_target_groups ({name}): {err}")
            tgs = {"TargetGroups": []}
        for tg in tgs.get('TargetGroups', []) or []:
            tgarn = tg['TargetGroupArn']
            g.add_node(mk_id("tg", region, tgarn), tg.get('TargetGroupName', 'tg'), "target_group", region, details={"protocol": tg.get('Protocol'), "port": tg.get('Port')})
            g.add_edge(mk_id("edge", region, lbarn, tgarn), mk_id("lb", region, lbarn), mk_id("tg", region, tgarn), "lb→tg", "bind", "resource")
            # Targets
            th, err = safe_call(elb.describe_target_health, TargetGroupArn=tgarn)
            if err:
                warnings.append(f"[{region}] describe_target_health: {err}")
                th = {"TargetHealthDescriptions": []}
            for d in th.get('TargetHealthDescriptions', []) or []:
                t = d.get('Target', {})
                tid = t.get('Id')
                ttype = tg.get('TargetType')  # instance | ip | alb | lambda
                if ttype == 'lambda':
                    nid = mk_id("lambda", region, tid)
                    g.add_node(nid, tid.split(":")[-1], "lambda", region)
                elif ttype == 'instance':
                    nid = mk_id("i", region, tid)
                    g.add_node(nid, tid, "instance", region)
                else:  # ip/alb
                    nid = mk_id(ttype or 'target', region, str(tid))
                    g.add_node(nid, str(tid), ttype or 'target', region)
                g.add_edge(mk_id("edge", region, tgarn, str(tid)), mk_id("tg", region, tgarn), nid, f"{tg.get('Protocol')}:{tg.get('Port')}", "tg-target", "network")


def enumerate_lambda(session, region: str, g: Graph, warnings: List[str]):
    lam = session.client('lambda', region_name=region, config=BOTO_CFG)
    try:
        paginator = lam.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []) or []:
                arn = fn['FunctionArn']
                name = fn['FunctionName']
                g.add_node(mk_id("lambda", region, arn), name, "lambda", region, details={"runtime": fn.get('Runtime')})
                # VPC config
                if fn.get('VpcConfig'):
                    for sid in fn['VpcConfig'].get('SubnetIds', []) or []:
                        g.add_edge(mk_id("edge", region, arn, sid), mk_id("lambda", region, arn), mk_id("subnet", region, sid), "in-subnet", "attach", "resource")
                    for sgid in fn['VpcConfig'].get('SecurityGroupIds', []) or []:
                        g.add_edge(mk_id("edge", region, arn, sgid), mk_id("lambda", region, arn), mk_id("sg", region, sgid), "has-sg", "attach", "resource")
    except ClientError as e:
        warnings.append(f"[{region}] Lambda list_functions: {e.response['Error'].get('Code')}")


def enumerate_eks(session, region: str, g: Graph, warnings: List[str]):
    eks = session.client('eks', region_name=region, config=BOTO_CFG)
    try:
        clusters = eks.list_clusters().get('clusters', [])
    except ClientError as e:
        warnings.append(f"[{region}] EKS list_clusters: {e.response['Error'].get('Code')}")
        clusters = []
    for c in clusters:
        try:
            d = eks.describe_cluster(name=c)['cluster']
            arn = d['arn']
            g.add_node(mk_id("eks", region, arn), c, "eks_cluster", region, details={"endpointPublic": d.get('resourcesVpcConfig', {}).get('endpointPublicAccess')})
            for sid in d.get('resourcesVpcConfig', {}).get('subnetIds', []) or []:
                g.add_edge(mk_id("edge", region, arn, sid), mk_id("eks", region, arn), mk_id("subnet", region, sid), "subnet", "attach", "resource")
            for sgid in d.get('resourcesVpcConfig', {}).get('securityGroupIds', []) or []:
                g.add_edge(mk_id("edge", region, arn, sgid), mk_id("eks", region, arn), mk_id("sg", region, sgid), "sg", "attach", "resource")
        except ClientError as e:
            warnings.append(f"[{region}] EKS describe_cluster({c}): {e.response['Error'].get('Code')}")


def enumerate_rds(session, region: str, g: Graph, warnings: List[str]):
    rds = session.client('rds', region_name=region, config=BOTO_CFG)
    try:
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []) or []:
                arn = db.get('DBInstanceArn') or db['DBInstanceIdentifier']
                name = db['DBInstanceIdentifier']
                g.add_node(mk_id("rds", region, arn), name, "rds_instance", region, details={"engine": db.get('Engine'), "status": db.get('DBInstanceStatus')})
                if db.get('DBSubnetGroup'):
                    for sn in db['DBSubnetGroup'].get('Subnets', []) or []:
                        sid = sn.get('SubnetIdentifier')
                        if sid:
                            g.add_edge(mk_id("edge", region, arn, sid), mk_id("rds", region, arn), mk_id("subnet", region, sid), "subnet", "attach", "resource")
                for vsg in db.get('VpcSecurityGroups', []) or []:
                    sgid = vsg.get('VpcSecurityGroupId')
                    if sgid:
                        g.add_edge(mk_id("edge", region, arn, sgid), mk_id("rds", region, arn), mk_id("sg", region, sgid), "sg", "attach", "resource")
    except ClientError as e:
        code = e.response['Error'].get('Code')
        warnings.append(f"[{region}] RDS describe_db_instances: {code}")


def enumerate_dynamodb(session, region: str, g: Graph, warnings: List[str]):
    ddb = session.client('dynamodb', region_name=region, config=BOTO_CFG)
    try:
        paginator = ddb.get_paginator('list_tables')
        for page in paginator.paginate():
            for t in page.get('TableNames', []) or []:
                g.add_node(mk_id("dynamodb", region, t), t, "dynamodb_table", region)
    except ClientError as e:
        warnings.append(f"[{region}] DynamoDB list_tables: {e.response['Error'].get('Code')}")


# Global S3 listing once (outside regions)
def enumerate_s3(session, g: Graph, warnings: List[str]):
    s3 = session.client('s3', config=BOTO_CFG)
    try:
        res = s3.list_buckets()
        for b in res.get('Buckets', []) or []:
            bname = b['Name']
            # Location (may be None/us-east-1 default)
            loc = "us-east-1"
            try:
                lr = s3.get_bucket_location(Bucket=bname)
                loc = (lr.get('LocationConstraint') or "us-east-1")
            except ClientError:
                pass
            g.add_node(mk_id("s3", loc, bname), bname, "s3_bucket", loc)
    except ClientError as e:
        warnings.append(f"[global] S3 list_buckets: {e.response['Error'].get('Code')}")


# ------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------
def build_session(ak: Optional[str], sk: Optional[str], st: Optional[str], profile: Optional[str]):
    if profile:
        return boto3.Session(profile_name=profile)
    if ak and sk:
        return boto3.Session(aws_access_key_id=ak, aws_secret_access_key=sk, aws_session_token=st)
    return boto3.Session()


def discover_regions(root_session) -> Tuple[List[str], List[str]]:
    warnings: List[str] = []
    try:
        ec2 = root_session.client('ec2', region_name='us-east-1', config=BOTO_CFG)
        data = ec2.describe_regions(AllRegions=False)
        regs = [r['RegionName'] for r in data.get('Regions', [])]
        return regs or DEFAULT_REGIONS, warnings
    except ClientError as e:
        warnings.append(f"describe_regions: {e.response['Error'].get('Code')} – falling back to defaults")
    except Exception as e:
        warnings.append(f"describe_regions error: {e} – falling back to defaults")
    return DEFAULT_REGIONS, warnings


def enumerate_all(payload: Dict[str, Any]) -> Dict[str, Any]:
    ak = payload.get('access_key_id')
    sk = payload.get('secret_access_key')
    st = payload.get('session_token')
    profile = payload.get('profile')
    regions = payload.get('regions') or []

    toggles = SERVICE_TOGGLES.copy()
    # Allow UI to flip services
    for k in list(toggles.keys()):
        if k in payload:
            toggles[k] = bool(payload[k])

    root_sess = build_session(ak, sk, st, profile)
    warnings: List[str] = []

    # Who am I?
    account_id = None
    caller_arn = None
    try:
        sts = root_sess.client('sts', config=BOTO_CFG)
        ident = sts.get_caller_identity()
        account_id = ident.get('Account')
        caller_arn = ident.get('Arn')
    except Exception as e:
        warnings.append(f"sts.get_caller_identity failed: {e}")

    # Regions
    if not regions or regions == ["ALL"]:
        auto_regions, wrn = discover_regions(root_sess)
        warnings.extend(wrn)
        regions = auto_regions

    g = Graph()

    # Global services first (S3), under root session
    if toggles.get('s3'):
        enumerate_s3(root_sess, g, warnings)

    # Region-parallel enumeration
    with ThreadPoolExecutor(max_workers=min(WORKERS, max(1, len(regions)))) as pool:
        futures = []
        for r in regions:
            # Per-region session to respect config/STS caching
            sess = build_session(ak, sk, st, profile)
            def job(region=r, session=sess):
                local_warnings: List[str] = []
                # EC2 infra
                if toggles.get('ec2'):
                    enumerate_ec2(session, region, g, local_warnings)
                if toggles.get('elbv2'):
                    enumerate_elbv2(session, region, g, local_warnings)
                if toggles.get('lambda'):
                    enumerate_lambda(session, region, g, local_warnings)
                if toggles.get('eks'):
                    enumerate_eks(session, region, g, local_warnings)
                if toggles.get('rds'):
                    enumerate_rds(session, region, g, local_warnings)
                if toggles.get('dynamodb'):
                    enumerate_dynamodb(session, region, g, local_warnings)
                return local_warnings
            futures.append(pool.submit(job))
        for f in as_completed(futures):
            try:
                warnings.extend(f.result())
            except Exception as e:
                warnings.append(f"worker error: {e}")

    return {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "elements": g.elements(),
        "warnings": warnings,
    }


# ------------------------------------------------------------
# Web app
# ------------------------------------------------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE


@app.post("/enumerate")
async def enumerate_api(req: Request):
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    try:
        result = enumerate_all(payload)
        return JSONResponse(result)
    except NoCredentialsError:
        return JSONResponse({"error": "No AWS credentials provided or found in environment/profile."}, status_code=400)
    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/_health")
async def health():
    return {"ok": True}


@app.get("/_selftest")
async def selftest():
    tests: List[Dict[str, Any]] = []

    def check(name: str, fn):
        try:
            fn()
            tests.append({"name": name, "ok": True})
        except AssertionError as e:
            tests.append({"name": name, "ok": False, "error": str(e)})
        except Exception as e:
            tests.append({"name": name, "ok": False, "error": f"unexpected: {e}"})

    # --- Unit tests (do not call AWS) ---
    def test_classify_target_type():
        assert classify_target_type("igw-123") == "igw", "igw mapping"
        assert classify_target_type("nat-abc") == "natgw", "nat mapping"
        assert classify_target_type("tgw-1") == "tgw", "tgw mapping"
        assert classify_target_type("pcx-1") == "pcx", "pcx mapping"
        assert classify_target_type("eni-1") == "eni", "eni mapping"
        assert classify_target_type("i-123") == "i", "instance mapping"
        assert classify_target_type("foo") == "target", "default mapping"

    def test_mk_id():
        assert mk_id("a", "", None, "b") == "a:b", "mk_id join"
        # extra cases
        assert mk_id("", None, "x") == "x", "mk_id drops empties"
        assert mk_id("x", "y") == "x:y", "mk_id basic"

    def test_range_to_str():
        assert range_to_str(80, 80, "tcp") == "80", "single port"
        assert range_to_str(80, 443, "tcp") == "80-443", "range"
        assert range_to_str(None, None, "tcp") == "all", "all default"
        assert range_to_str(0, 0, "-1") == "all", "proto all"
        # extra cases
        assert range_to_str(53, 53, "udp") == "53", "udp single"
        assert range_to_str(1000, 2000, "tcp") == "1000-2000", "tcp range"
        assert range_to_str(0, 0, "all") == "all", "proto all keyword"

    def test_graph_merge_details():
        g = Graph()
        g.add_node("n:a", "A", "t", "r", details={"k": "v"})
        g.add_node("n:a", "A", "t", "r", details={"k2": "v2"})
        matches = [e for e in g.elements() if e.get("data", {}).get("id") == "n:a"]
        assert matches, "node should exist"
        d = matches[0]["data"]["details"]
        assert d.get("k") == "v" and d.get("k2") == "v2", "details should merge"

    check("classify_target_type", test_classify_target_type)
    check("mk_id", test_mk_id)
    check("range_to_str", test_range_to_str)
    check("graph_merge_details", test_graph_merge_details)

    return {"ok": all(t.get("ok") for t in tests), "tests": tests}


# ------------------------------------------------------------
# Frontend (Cytoscape) – single page, inline
# ------------------------------------------------------------
HTML_PAGE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AWS Topology Enumerator</title>
  <script src="https://unpkg.com/cytoscape@3.27.0/dist/cytoscape.min.js"></script>
  <style>
    body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
    .app { display: grid; grid-template-columns: 340px 1fr; grid-template-rows: auto 1fr; height: 100vh; }
    header { grid-column: 1 / 3; padding: 10px 14px; border-bottom: 1px solid #eee; display:flex; gap:14px; align-items:center; }
    header h1 { font-size: 18px; margin: 0; font-weight: 600; }
    header .meta { color:#666; font-size:12px; }
    .sidebar { padding: 12px; border-right: 1px solid #eee; overflow: auto; }
    .section { margin-bottom: 14px; }
    .section h3 { margin: 10px 0 8px; font-size: 14px; }
    label { display:block; font-size:12px; margin: 6px 0 4px; color:#333; }
    input[type=text], input[type=password] { width:100%; padding:8px; border:1px solid #ddd; border-radius:8px; font-size:13px; }
    .row { display:flex; gap:8px; }
    .row > div { flex:1; }
    button { padding: 8px 10px; border: 1px solid #ddd; background:#fff; border-radius:8px; cursor:pointer; }
    button.primary { background:#0ea5e9; border-color:#0ea5e9; color:#fff; }
    button:disabled { opacity: .6; cursor:not-allowed; }
    .legend { display:flex; gap:10px; align-items:center; font-size:12px; }
    .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
    #cy { width: 100%; height: calc(100vh - 56px); }
    .panel { padding: 10px; border-top:1px solid #eee; font-size:12px; background:#fafafa; height: 32vh; overflow:auto; }
    .warn { color:#b45309; background:#fffbeb; border:1px solid #f59e0b; padding:8px; border-radius:8px; margin:6px 0; }
    .small { font-size:12px; color:#666; }
    pre { white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <div class="app">
    <header>
      <h1>AWS Topology Enumerator</h1>
      <div class="meta" id="meta"></div>
      <div style="margin-left:auto; display:flex; gap:8px;">
        <button id="fit">Fit</button>
        <button id="layout">Re‑Layout</button>
      </div>
    </header>
    <div class="sidebar">
      <div class="section">
        <h3>Credentials</h3>
        <label>Profile name (optional)</label>
        <input id="profile" type="text" placeholder="e.g. default" />
        <div class="small">If set, environment/shared config is used. Leave blank to paste keys or use env.</div>
        <div class="row">
          <div>
            <label>Access Key ID</label>
            <input id="ak" type="text" />
          </div>
          <div>
            <label>Secret Access Key</label>
            <input id="sk" type="password" />
          </div>
        </div>
        <label>Session Token (optional)</label>
        <input id="st" type="text" />
      </div>
      <div class="section">
        <h3>Scope</h3>
        <label>Regions (comma‑separated). Use ALL for all available.</label>
        <input id="regions" type="text" placeholder="ap-southeast-1,us-east-1 or ALL" />
        <div class="row" style="margin-top:8px;">
          <button id="quick-sg">Use ap‑southeast‑1</button>
          <button id="quick-all">All regions</button>
        </div>
      </div>
      <div class="section">
        <h3>Services</h3>
        <div><label><input type="checkbox" id="svc-ec2" checked> EC2/VPC/SG</label></div>
        <div><label><input type="checkbox" id="svc-elbv2" checked> ALB/NLB</label></div>
        <div><label><input type="checkbox" id="svc-lambda" checked> Lambda</label></div>
        <div><label><input type="checkbox" id="svc-eks" checked> EKS</label></div>
        <div><label><input type="checkbox" id="svc-rds" checked> RDS</label></div>
        <div><label><input type="checkbox" id="svc-dynamodb" checked> DynamoDB</label></div>
        <div><label><input type="checkbox" id="svc-s3" checked> S3 (global)</label></div>
      </div>
      <div class="section">
        <button id="run" class="primary">Enumerate</button>
        <span id="status" class="small"></span>
      </div>
      <div class="section">
        <h3>Legend</h3>
        <div class="legend"><span class="dot" style="background:#2563eb"></span> Resource edge</div>
        <div class="legend"><span class="dot" style="background:#f97316"></span> Network/protocol edge</div>
      </div>
      <div class="section">
        <h3>Warnings</h3>
        <div id="warnings"></div>
      </div>
    </div>
    <div>
      <div id="cy"></div>
      <div class="panel" id="panel"><div class="small">Select a node or edge to see details.</div></div>
    </div>
  </div>

<script>
  let cy;
  function initCy() {
    cy = cytoscape({
      container: document.getElementById('cy'),
      elements: [],
      style: [
        { selector: 'node', style: { 'label': 'data(label)', 'font-size': 10, 'text-wrap': 'wrap', 'text-max-width': 120, 'background-color': '#94a3b8' }},
        { selector: 'node[type = "instance"]', style: { 'shape': 'round-rectangle', 'background-color': '#10b981' }},
        { selector: 'node[type = "security_group"]', style: { 'shape': 'hexagon', 'background-color': '#a855f7' }},
        { selector: 'node[type = "subnet"]', style: { 'shape': 'rectangle', 'background-color': '#22c55e' }},
        { selector: 'node[type = "vpc"]', style: { 'shape': 'rectangle', 'background-color': '#16a34a' }},
        { selector: 'node[type = "route_table"]', style: { 'shape': 'rectangle', 'background-color': '#15803d' }},
        { selector: 'node[type = "igw"]', style: { 'shape': 'triangle', 'background-color': '#f43f5e' }},
        { selector: 'node[type = "nat_gateway"]', style: { 'shape': 'triangle', 'background-color': '#ea580c' }},
        { selector: 'node[type = "eni"]', style: { 'shape': 'ellipse', 'background-color': '#64748b' }},
        { selector: 'node[type = "load_balancer"]', style: { 'shape': 'round-rectangle', 'background-color': '#0ea5e9' }},
        { selector: 'node[type = "target_group"]', style: { 'shape': 'round-rectangle', 'background-color': '#38bdf8' }},
        { selector: 'node[type = "lambda"]', style: { 'shape': 'round-rectangle', 'background-color': '#f59e0b' }},
        { selector: 'node[type = "eks_cluster"]', style: { 'shape': 'round-rectangle', 'background-color': '#06b6d4' }},
        { selector: 'node[type = "rds_instance"]', style: { 'shape': 'round-rectangle', 'background-color': '#3b82f6' }},
        { selector: 'node[type = "dynamodb_table"]', style: { 'shape': 'round-rectangle', 'background-color': '#6366f1' }},
        { selector: 'node[type = "s3_bucket"]', style: { 'shape': 'round-rectangle', 'background-color': '#84cc16' }},
        { selector: 'node[type = "aws_service"]', style: { 'shape': 'round-rectangle', 'background-color': '#9ca3af' }},
        { selector: 'node[type = "cidr"], node[type = "prefix_list"], node[type = "external"]', style: { 'shape': 'ellipse', 'background-color': '#fca5a5' }},

        { selector: 'edge', style: { 'curve-style': 'bezier', 'width': 1, 'line-color': '#64748b', 'target-arrow-shape': 'vee', 'target-arrow-color': '#64748b', 'label': 'data(label)', 'font-size': 9 }},
        { selector: 'edge[connectionType = "resource"]', style: { 'line-color': '#2563eb', 'target-arrow-color': '#2563eb' }},
        { selector: 'edge[connectionType = "network"]', style: { 'line-color': '#f97316', 'target-arrow-color': '#f97316' }},
      ],
      layout: { name: 'cose', padding: 20, animate: false }
    });

    cy.on('tap', 'node, edge', function(evt){
      const d = evt.target.data();
      const panel = document.getElementById('panel');
      panel.innerHTML = `<b>${d.label || d.id}</b><br/><span class="small">type: ${d.type || ''} &nbsp; region: ${d.region || ''}</span><pre>${JSON.stringify(d.details || d, null, 2)}</pre>`;
    });
  }

  initCy();

  function setStatus(txt){ document.getElementById('status').innerText = txt; }
  function setMeta(txt){ document.getElementById('meta').innerText = txt; }
  function addWarnings(w){
    const out = document.getElementById('warnings');
    out.innerHTML = '';
    (w||[]).forEach(x => { const div = document.createElement('div'); div.className='warn'; div.innerText=x; out.appendChild(div); });
  }

  document.getElementById('quick-sg').onclick = () => { document.getElementById('regions').value = 'ap-southeast-1'; };
  document.getElementById('quick-all').onclick = () => { document.getElementById('regions').value = 'ALL'; };

  document.getElementById('fit').onclick = () => cy.fit();
  document.getElementById('layout').onclick = () => cy.layout({ name:'cose', padding:20, animate:false }).run();

  document.getElementById('run').onclick = async () => {
    setStatus('Enumerating… this can take a bit.');
    addWarnings([]);
    const payload = {
      profile: document.getElementById('profile').value.trim() || undefined,
      access_key_id: document.getElementById('ak').value.trim() || undefined,
      secret_access_key: document.getElementById('sk').value.trim() || undefined,
      session_token: document.getElementById('st').value.trim() || undefined,
      ec2: document.getElementById('svc-ec2').checked,
      elbv2: document.getElementById('svc-elbv2').checked,
      lambda: document.getElementById('svc-lambda').checked,
      eks: document.getElementById('svc-eks').checked,
      rds: document.getElementById('svc-rds').checked,
      dynamodb: document.getElementById('svc-dynamodb').checked,
      s3: document.getElementById('svc-s3').checked,
    };
    const rtxt = document.getElementById('regions').value.trim();
    if (rtxt) {
      payload.regions = rtxt.toUpperCase() === 'ALL' ? ['ALL'] : rtxt.split(',').map(s => s.trim()).filter(Boolean);
    }

    try {
      const res = await fetch('/enumerate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
      const data = await res.json();
      if(!res.ok){ throw new Error(data.error || 'Request failed'); }
      setMeta(`${data.account_id ? 'Account ' + data.account_id + ' – ' : ''}${data.caller_arn || ''}`);
      addWarnings(data.warnings);
      cy.elements().remove();
      cy.add(data.elements || []);
      cy.layout({ name:'cose', padding:20, animate:false }).run();
      cy.fit();
      setStatus(`Done. ${data.elements ? data.elements.length : 0} elements.`);
    } catch(err){
      addWarnings([String(err)]);
      setStatus('Error.');
    }
  };
</script>
</body>
</html>
"""

if __name__ == "__main__":
    # Optional: run self-tests on startup if requested
    if os.environ.get("RUN_SELF_TESTS") == "1":
        import doctest
        doctest.testmod(verbose=True)
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
