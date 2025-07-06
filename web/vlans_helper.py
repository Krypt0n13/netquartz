# vlans_helper.py
import json
import os
from pysnmp.hlapi import *

VLANS_FILE = 'vlans.json'

def snmp_get_vlans(ip, community):
    vlans = []
    vlan_name_oid = ObjectIdentity('1.3.6.1.4.1.9.9.46.1.3.1.1.4')  # Cisco VLAN name

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(vlan_name_oid),
        lexicographicMode=False
    ):
        if errorIndication:
            raise Exception(str(errorIndication))
        elif errorStatus:
            raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex}')
        else:
            for varBind in varBinds:
                oid, value = varBind
                vlan_id = oid.prettyPrint().split('.')[-1]
                vlan_name = value.prettyPrint()
                vlans.append({'id': vlan_id, 'name': vlan_name})

    hostname = resolve_hostname(ip, community)
    return vlans, hostname

def resolve_hostname(ip, community):
    try:
        for (errInd, errStat, errIdx, binds) in getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))  # sysName
        ):
            if errInd or errStat:
                return ip
            return str(binds[0][1])
    except Exception:
        return ip

def save_vlans(vlans, hostname):
    if os.path.exists(VLANS_FILE):
        with open(VLANS_FILE, 'r') as f:
            existing = json.load(f)
    else:
        existing = []

    vlan_lookup = {}
    for entry in existing:
        key = (entry["id"], entry["name"])
        vlan_lookup.setdefault(key, set()).update(entry["hostname"].split(", "))

    for vlan in vlans:
        key = (vlan["id"], vlan["name"])
        vlan_lookup.setdefault(key, set()).add(hostname)

    merged = []
    for (vlan_id, vlan_name), hostnames in vlan_lookup.items():
        merged.append({
            "id": vlan_id,
            "name": vlan_name,
            "hostname": ", ".join(sorted(hostnames))
        })

    with open(VLANS_FILE, 'w') as f:
        json.dump(merged, f, indent=2)

def load_vlans():
    if os.path.exists(VLANS_FILE):
        with open(VLANS_FILE, 'r') as f:
            return json.load(f)
    return []
