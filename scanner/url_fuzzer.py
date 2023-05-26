from urllib.parse import urljoin
import requests
import os
import concurrent.futures
from scanner.objects import UrlFuzzResult, UrlScanResult

forbidden_status_codes = [400, 401, 403, 404, 405, 406, 407, 408, 409, 410, 411, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]

def init_db_fuzz_object(id, db):
    return db.urls.insert_one({
        '_id': id,
        'status': 'PENDING',
    })

def fuzz_urls(domain, db, scan_id):
    scan_results = UrlFuzzResult.URLFuzzResult(domain, db, scan_id)

    path = os.path.dirname(__file__)

    # detect os
    if os.name == 'nt':
        path = os.path.join(path, '..\\resources\\fuzz_url.txt')
    else:
        path = os.path.join(path, '../resources/fuzz_url.txt')

    def fuzz_url(url):
        nonlocal db
        try:
            response = requests.get(url=url, timeout=3)
            if response.status_code not in forbidden_status_codes:
                scan_results.append(UrlScanResult.URLScanResult(url, response.status_code))
        except Exception:
            pass

        scan_results.total_scanned += 1

        if scan_results.total_scanned % 100 == 0:
            db.urls.update_one({'_id': scan_id}, {'$set': {'total_scanned': scan_results.total_scanned}})

    with open(path, 'r') as file:
        lines = file.readlines()

        db.urls.update_one({'_id': scan_id}, {'$set': {
            'total_to_scan': len(lines),
            'total_scanned': 0,
            'total_found': 0,
        }})

        urls = [urljoin(domain, fuzzer.strip()) for fuzzer in lines]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(fuzz_url, urls)
    
    scan_results.save_to_mongo()

    return scan_results

if __name__ == '__main__':
    url = 'https://www.uphf.fr'
    print(fuzz_urls(url))