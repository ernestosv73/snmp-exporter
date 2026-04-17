#!/usr/bin/env python3
# monitor_interfaces.py
# Requiere: pip install easysnmp
# Sistema:  sudo apt-get install libsnmp-dev snmp-mibs-downloader

from easysnmp import Session, EasySNMPError
import json


def get_interface_data(host, community='public', port=161):
    """Query interface statistics via SNMP usando easysnmp."""

    session = Session(
        hostname=host,
        community=community,
        version=2,
        remote_port=port,
        use_long_names=True,
        use_numeric=True,
    )

    oids = [
        ('ifDescr',       '1.3.6.1.2.1.2.2.1.2'),
        ('ifOperStatus',  '1.3.6.1.2.1.2.2.1.8'),
        ('ifHCInOctets',  '1.3.6.1.2.1.31.1.1.1.6'),
        ('ifHCOutOctets', '1.3.6.1.2.1.31.1.1.1.10'),
        ('ifInErrors',    '1.3.6.1.2.1.2.2.1.14'),
    ]

    results = {}

    for oid_name, oid_base in oids:
        results[oid_name] = {}
        try:
            for vb in session.walk(oid_base):
                results[oid_name][vb.oid_index] = vb.value
        except EasySNMPError as exc:
            print(f"[WARN] Error consultando {oid_name} ({oid_base}): {exc}")

    return results


if __name__ == '__main__':
    device = '172.20.20.2'   # dirección IPv4 — evita bug easysnmp #47 con IPv6
    data = get_interface_data(device)
    print(json.dumps(data, indent=2))
