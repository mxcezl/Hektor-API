from scanner.url_fuzzer import fuzz_urls

def perform_scan_background(domain, db, scan_id):
    results = fuzz_urls(domain)
    results.save_to_mongo(db, scan_id)