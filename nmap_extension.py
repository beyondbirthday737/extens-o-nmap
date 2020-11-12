import sys

try:
    import nmap
except:
    sys.exit("[!] INSTALL THE NMAP LIBRARY \n --> pip install python-nmap")


if (len(sys.argv) != 3):
    sys.exit("Please provide two arguments the first being the targets the second the ports")


class Scanner:
    def __init__(self, addrs, port):
        self.address = addrs
        self.ports = port

        self.nmap_scan = nmap.PortScanner()

    def init_scan(self):
        self.nmap_scan.scan(self.address, self.ports)

        for host in self.nmap_scan.all_hosts():
            if not self.nmap_scan[host].hostname():
                print(f"The host's IP address is {host} and it's hostname was not found")
            else:
                print(f"The host's IP address is {host} and it's hostame is {self.nmap_scan[host].hostname()}")


ports = str(sys.argv[2])
address = str(sys.argv[1])

scan = Scanner(address, ports)
scan.init_scan()
