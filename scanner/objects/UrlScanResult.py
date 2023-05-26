class URLScanResult:
    def __init__(self, url, status_code):
        self.url = url
        self.status_code = status_code

    def to_dict(self):
        return {
            'url': self.url,
            'status_code': self.status_code
        }