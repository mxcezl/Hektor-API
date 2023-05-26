from .UrlScanResult import URLScanResult

class URLFuzzResult:
    def __init__(self, domain: str):
        self.urls = []
        self.domain = domain
        self.id = None

    def append(self, url_scan_result: URLScanResult):
        self.urls.append(url_scan_result.to_dict())  # convert to dictionary here
        self.total_scanned = len(self.urls)

    def to_dict(self):
        return {
            'id': str(self.id),
            'domain': self.domain,
            'urls': self.urls,
        }
    
    def save_to_mongo(self, db):
        # Insert the urls into the MongoDB collection
        result = db.urls.insert_one({
            'domain': self.domain,
            'urls': self.urls
            })

        # Set the id of this object to the generated _id
        self.id = result.inserted_id
