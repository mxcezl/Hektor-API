class Host:
    def __init__(self, domain, ip):
        self.domain = domain
        self.ip = ip

    def to_dict(self):
        return {
            'domain': self.domain,
            'ip': self.ip,
        }
