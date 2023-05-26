import sys
from .PortScanResultPerIP import IPScanResult

class IPFuzzResult:
    def __init__(self, ips: list[IPScanResult], db, id: str = None):
        self.id = id
        self.ips = ips
        self.status = 'PENDING'
        self.results = []
        self.db = db

    def append(self, ip: IPScanResult):
        self.results.append(ip.to_dict())
        self.db.ports.update_one({'_id': self.id}, {'$set': {'results': self.results}})

    def to_dict(self):
        return {
            'id': str(self.id),
            'ips': self.ips,
            'status': self.status,
        }

    def save_to_mongo(self):
        self.db.ports.update_one({'_id': self.id}, {'$set': {
            'status': 'FINISHED',
            'ips': self.ips
        }})