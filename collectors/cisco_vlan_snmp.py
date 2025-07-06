import json
import sys

if __name__ == "__main__":
    ip = sys.argv[1]
    community = sys.argv[2]
    # SNMP-Abfrage simulieren
    data = {
        "hostname": "Switch-" + ip.replace('.', '-'),
        "vlans": [
            {"id": 1, "name": "default"},
            {"id": 10, "name": "Management"},
            {"id": 20, "name": "VoIP"}
        ]
    }
    print(json.dumps(data))
