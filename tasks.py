from scanner.port_scanner import scan_ip
from scanner.url_fuzzer import fuzz_urls

def perform_url_scan_background(domain, db, scan_id):
    results = fuzz_urls(domain, db, scan_id)

def perform_ports_scan_background(ip, db, scan_id):
    results = scan_ip(ip, db, scan_id)