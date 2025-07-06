from pysnmp.hlapi import *

def get_cisco_vlans(ip, community):
    vlan_oid = ObjectIdentity('1.3.6.1.4.1.9.9.46.1.3.1.1.4')  # vmVlanName
    found = False

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=2, retries=1),
        ContextData(),
        ObjectType(vlan_oid),
        lexicographicMode=False
    ):
        if errorIndication:
            print(f"❌ Fehler: {errorIndication}")
            break
        elif errorStatus:
            print(f"⚠️ SNMP Fehler: {errorStatus.prettyPrint()}")
            break
        else:
            for varBind in varBinds:
                oid, val = varBind
                vlan_index = oid.prettyPrint().split('.')[-1]
                print(f"📡 VLAN-ID: {vlan_index} → Name: {val.prettyPrint()}")
                found = True

    if not found:
        print("⚠️ Keine VLAN-Daten gefunden.")

# Beispiel-Aufruf
get_cisco_vlans("192.168.178.107", "public")
