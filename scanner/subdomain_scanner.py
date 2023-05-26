from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI

from scanner.objects.Host import Host
from scanner.objects.SubdomainScanResult import SubDomainScanResult

def scan_domain(domain):
    results = DNSDumpsterAPI().search(domain)
    records = results['dns_records']['host']
    mapped_records = [Host(record['domain'], record['ip']) for record in records]
    return SubDomainScanResult(mapped_records)

if __name__ == '__main__':
    print(scan_domain('google.com'))
