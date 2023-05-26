import sys
import requests
import os
from scanner.objects import UrlFuzzResult, UrlScanResult

forbidden_status_codes = [400, 401, 403, 404, 405, 406, 407, 408, 409, 410, 411, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]

def init_db_fuzz_object(id, db):
    return db.urls.insert_one({
        '_id': id,
        'status': 'PENDING',
    })

def fuzz_urls(domain):
    scan_results = UrlFuzzResult.URLFuzzResult(domain)
    path = os.path.join(os.path.dirname(__file__), '..\\resources\\fuzz_url.txt')
    with open(path, 'r') as file:
        lines = file.readlines()
        for fuzzer in lines:
            url = f"{domain}/{fuzzer}"
            try:
                response = requests.get(url=url, timeout=5)
                if response.status_code not in forbidden_status_codes:
                    scan_results.append(UrlScanResult.URLScanResult(url, response.status_code))
            except Exception:
                pass
    return scan_results

if __name__ == '__main__':
    url = 'https://www.uphf.fr'
    print(fuzz_urls(url))