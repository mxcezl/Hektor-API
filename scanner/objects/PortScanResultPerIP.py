class IPScanResult:
    def __init__(self, ip: str, db, id, error: str = None):
        self.ip = ip
        self.open_ports = None
        self.error = error
        self.id = id
        self.db = db
        
    def append_port(self, port: int, service: str):
        if self.open_ports is None:
            self.open_ports = []
        self.open_ports.append({'port': port, 'service': service})
        
    def to_dict(self):
        if not self.error:
            return {
                'ip': self.ip,
                'open_ports': self.open_ports,
            }
        
        return {
            'ip': self.ip,
            'open_ports': self.open_ports,
            'error': self.error,
        }
    
    def save_mongo(self):
        if self.open_ports is None:
            self.open_ports = []
        self.db.ports.update_one({'_id': self.id, 'ip': self.ip}, {'$set': self.to_dict()})