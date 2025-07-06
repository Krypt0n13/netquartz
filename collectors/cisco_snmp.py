from pysnmp.hlapi import *
import json
import sys

def snmp_get(ip, community, oid):
    error_indication, error_status, error_index, var_binds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
    )
    if error_indication or error_status:
        return None
    for var_bind in var_binds:
        return var_bind[1].prettyPrint()
    return None

def snmp_walk(ip, community, oid):
    result = {}
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus:
            break
        for varBind in varBinds:
            index = varBind[0].prettyPrint().split('.')[-1]
            result[index] = varBind[1].prettyPrint()
    return result

def get_device_info(ip, community):
    return {
        "hostname": snmp_get(ip, community, "1.3.6.1.2.1.1.5.0"),
        "model": snmp_get(ip, community, "1.3.6.1.2.1.1.1.0"),
        "serial": "N/A",
        "location": snmp_get(ip, community, "1.3.6.1.2.1.1.6.0"),
        "uptime": snmp_get(ip, community, "1.3.6.1.2.1.1.3.0")
    }

def get_vlans(ip, community):
    vlan_oid = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"
    result = []
    print(f"[DEBUG] Trying Cisco VLAN OID {vlan_oid}...", file=sys.stderr)

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(vlan_oid)),
        lexicographicMode=False
    ):
        if errorIndication:
            print(f"[ERROR] SNMP Error: {errorIndication}", file=sys.stderr)
            break
        if errorStatus:
            print(f"[ERROR] SNMP Status: {errorStatus.prettyPrint()}", file=sys.stderr)
            break
        for varBind in varBinds:
            vlan_id = varBind[0].prettyPrint().split('.')[-1]
            vlan_name = varBind[1].prettyPrint()
            print(f"[FOUND - Cisco] VLAN {vlan_id}: {vlan_name}", file=sys.stderr)
            result.append({"vlan_id": vlan_id, "name": vlan_name})

    if not result:
        print("[DEBUG] No VLANs found – result is empty.", file=sys.stderr)

    return result

def get_interface_details(ip, community):
    descrs = snmp_walk(ip, community, '1.3.6.1.2.1.2.2.1.2')        # ifDescr
    aliases = snmp_walk(ip, community, '1.3.6.1.2.1.31.1.1.1.18')    # ifAlias
    vlans  = snmp_walk(ip, community, '1.3.6.1.4.1.9.9.68.1.2.2.1.2') # vmVlan

    interfaces = []
    for idx, name in descrs.items():
        interfaces.append({
            "index": idx,
            "interface": name,
            "description": aliases.get(idx, ""),
            "vlan": vlans.get(idx, "")
        })
    return interfaces

def get_neighbors(ip, community):
    names = snmp_walk(ip, community, '1.0.8802.1.1.2.1.4.1.1.9')     # lldpRemSysName
    ports = snmp_walk(ip, community, '1.0.8802.1.1.2.1.4.1.1.8')     # lldpRemPortDesc

    neighbors = []
    for idx in names:
        neighbors.append({
            "local_port_index": idx,
            "neighbor_name": names.get(idx, ""),
            "neighbor_port": ports.get(idx, "")
        })
    return neighbors

def get_arp_table(ip, community):
    ips = snmp_walk(ip, community, '1.3.6.1.2.1.4.22.1.3')  # ip
    macs = snmp_walk(ip, community, '1.3.6.1.2.1.4.22.1.2') # mac

    arp = []
    for idx in ips:
        arp.append({
            "ip": ips[idx],
            "mac": macs.get(idx, "")
        })
    return arp

def run_discovery(ip, community):
    return {
        "device": get_device_info(ip, community),
        "interfaces": get_interface_details(ip, community),
        "ip_addresses": [],
        "vlans": get_vlans(ip, community),
        "neighbors": get_neighbors(ip, community),
        "arp_table": get_arp_table(ip, community)
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python cisco_snmp.py <IP> <COMMUNITY>", file=sys.stderr)
        sys.exit(1)

    ip = sys.argv[1]
    community = sys.argv[2]
    result = run_discovery(ip, community)
    json.dump(result, sys.stdout)  # ❗️WICHTIG: NUR diese Zeile gibt stdout aus
