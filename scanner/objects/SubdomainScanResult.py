from typing import List
import uuid
from scanner.objects.Host import Host

class SubDomainScanResult:
    def __init__(self, domain: str, hosts: List[Host], user: str, db, id):
        self.id = id
        self.hosts = hosts
        self.domain = domain
        self.username = user
        self.db = db
        if self.id is None:
            self.id = uuid.uuid4()
        if db.hosts.find_one({'_id': str(self.id)}) is None:
            db.hosts.insert_one({'_id': str(self.id), 'domain': self.domain, 'user': self.username, 'hosts': [host.to_dict() for host in self.hosts]})
        else:
            db.hosts.update_one({'_id': str(self.id)}, {'$set': {'user': self.username, 'hosts': [host.to_dict() for host in self.hosts]}})

    def to_dict(self):
        return {
            'domain': self.domain,
            'hosts': [host.to_dict() for host in self.hosts],
        }

    def save_to_mongo(self):
        # Convert hosts to a list of dictionaries
        hosts_dicts = [host.to_dict() for host in self.hosts]

        # Insert object into the MongoDB collection
        result = self.db.hosts.update_one({'_id': str(self.id),'domain': self.domain, 'user': self.username, 'hosts': hosts_dicts})
