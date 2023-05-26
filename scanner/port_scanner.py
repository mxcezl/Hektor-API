from concurrent.futures import ThreadPoolExecutor
import os
import socket
import concurrent.futures
import re
import sys
from ping3 import ping
from scanner.objects import IPScanResult, PortScanResultPerIP

def init_db_port_object(id, db, ips):
    return db.ports.insert_one({
        '_id': id,
        'ips': ips,
        'status': 'PENDING',
    })

def is_valid_ip(ip):
    """Validate IP address."""
    pattern = re.compile(
        r"^"
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        r"$"
    )
    return re.match(pattern, ip) is not None

def is_up(ip):
    """Check if host is up."""
    try:
        return ping(ip) is not None
    except Exception as e:
        return False

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        try:
            service = socket.getservbyport(port)
            return {'port': port, 'service': service}
        except Exception:
            pass
    sock.close()

def scan_ip(ip, scan_id, db):
    if not is_valid_ip(ip):
        return PortScanResultPerIP.IPScanResult(ip, error='invalid IP address')
    if not is_up(ip):
        return PortScanResultPerIP.IPScanResult(ip, error='host is down')
    open_ports = []

    path = os.path.dirname(__file__)

    # detect os
    if os.name == 'nt':
        path = os.path.join(path, '..\\resources\\top1000-nmap_ports.txt')
    else:
        path = os.path.join(path, '../resources/top1000-nmap_ports.txt')
        
    # Read ports in a file
    with open(path, 'r') as file:
        ports_to_scan = [int(port.strip()) for port in file.readlines()]

    scan_result = PortScanResultPerIP.IPScanResult(ip)

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports_to_scan]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None and result['port'] is not None and result['service'] is not None:
                scan_result.append_port(int(result['port']), str(result['service']))
                db.ports.update_one(
                        {'_id': scan_id, 'results.ip': ip},
                        {'$set': {'results.$.open_ports': scan_result.open_ports}}
                    )
            
    return scan_result

def scan_ips(ips, db, id=None):
    ip_fuzz_result = IPScanResult.IPFuzzResult(ips, db, id)
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_ip, ip, id, db) for ip in ips]
        for future in concurrent.futures.as_completed(futures):
            ip_scan_result = future.result()
            ip_fuzz_result.append(ip_scan_result)
    ip_fuzz_result.save_to_mongo()
    return ip_fuzz_result