from typing import List
from scanner.objects.Host import Host

class SubDomainScanResult:
    def __init__(self, hosts: List[Host], id: str = None):
        self.hosts = hosts
        self.id = id

    def to_dict(self):
        return {
            'hosts': [host.to_dict() for host in self.hosts],
            'id': str(self.id),
        }

    def save_to_mongo(self, db):
        # Convert hosts to a list of dictionaries
        hosts_dicts = [host.to_dict() for host in self.hosts]

        # Insert the hosts into the MongoDB collection
        result = db.hosts.insert_one({'hosts': hosts_dicts})

        # Set the id of this object to the generated _id
        self.id = result.inserted_id
