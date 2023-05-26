from .UrlScanResult import URLScanResult

class URLFuzzResult:
    def __init__(self, domain: str, db, id: str = None):
        self.urls = []
        self.domain = domain
        self.id = id
        self.total_to_scan = 0
        self.total_found = 0
        self.total_scanned = 0
        self.db = db

        if id is not None:
            self.db.urls.update_one({'_id': self.id}, {'$set': {
            'domain': self.domain,
        }})

    def append(self, url_scan_result: URLScanResult):
        self.urls.append(url_scan_result.to_dict())
        self.total_found = len(self.urls)
        self.db.urls.update_one({'_id': self.id}, {'$set': {
            'urls': self.urls,
            'total_found': len(self.urls),
            'total_scanned': len(self.urls),
        }})

    def to_dict(self):
        return {
            'id': str(self.id),
            'domain': self.domain,
            'urls': self.urls,
            'total_to_scan': self.total_to_scan,
            'total_found': self.total_found,
            'total_scanned': self.total_scanned,
        }
    
    def save_to_mongo(self):
        self.db.urls.update_one({'_id': self.id}, {'$set': {
            'status': 'FINISHED',
            'urls': self.urls,
            'domain': self.domain,
            'total_found': self.total_found,
            'total_scanned': self.total_scanned,
        }})
