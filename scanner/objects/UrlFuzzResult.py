from .UrlScanResult import URLScanResult

class URLFuzzResult:
    def __init__(self, domain: str, db, id: str = None):
        self.urls = []
        self.domain = domain
        self.id = id
        self.db = db

        if id is not None:
            self.db.urls.update_one({'_id': self.id}, {'$set': {
            'domain': self.domain,
        }})

    def append(self, url_scan_result: URLScanResult):
        self.urls.append(url_scan_result.to_dict())
        self.db.urls.update_one({'_id': self.id}, {'$set': {
            'urls': self.urls,
        }})

    def to_dict(self):
        return {
            'id': str(self.id),
            'domain': self.domain,
            'urls': self.urls,
        }
    
    def save_to_mongo(self):
        self.db.urls.update_one({'_id': self.id}, {'$set': {
            'status': 'FINISHED',
            'urls': self.urls,
            'domain': self.domain,
        }})
