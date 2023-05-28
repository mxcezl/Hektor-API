from typing import List
import uuid
from scanner.objects.Host import Host

class SubDomainScanResult:
    def __init__(self, domain: str, hosts: List[Host], user: str):
        self.hosts = hosts
        self.domain = domain
        self.username = user

    def to_dict(self):
        return {
            'domain': self.domain,
            'hosts': [host.to_dict() for host in self.hosts],
        }

    def save_to_mongo(self, db):
        # Convert hosts to a list of dictionaries
        hosts_dicts = [host.to_dict() for host in self.hosts]

        # Insert object into the MongoDB collection
        result = db.hosts.insert_one({'_id': str(uuid.uuid4()),'domain': self.domain, 'user': self.username, 'hosts': hosts_dicts})

        # Set the id of this object to the generated _id
        self.id = result.inserted_id
