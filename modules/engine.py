import socket
import ssl
import time
import random
import ipaddress
import os
from datetime import datetime
from rich import print as rprint

class IpManager:
    """Handles loading subnets from file and generating target IPs."""
    
    @staticmethod
    def load_subnets(filename):
        """Reads CIDR ranges from the specified file."""
        if not os.path.exists(filename):
            rprint(f"[red]Error: {filename} not found![/red]")
            return []
            
        with open(filename, 'r') as f:
            # Filter empty lines and comments
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    @staticmethod
    def generate_targets(subnets, randomize=True, sample_size=20):
        """
        Generates a list of IP addresses from subnets.
        If randomize is True, picks a random sample to avoid blocking.
        """
        target_ips = []
        for cidr in subnets:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if randomize:
                    # Smart sampling: pick random hosts
                    hosts = list(network.hosts())
                    k = min(len(hosts), sample_size)
                    target_ips.extend([str(ip) for ip in random.sample(hosts, k)])
                else:
                    # Full scan (use with caution)
                    target_ips.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                continue
        
        if randomize:
            random.shuffle(target_ips)
        return target_ips

class ScannerEngine:
    """Core scanning logic using TLS Handshake."""
    
    def __init__(self, config):
        self.config = config

    def check_ip(self, ip, stop_event):
        """
        Performs a TLS Handshake on the target IP using the SNI.
        Returns result dict if successful, None otherwise.
        """
        if stop_event.is_set(): return None

        # Setup SSL Context (Ignore hostname mismatch for direct IP scanning)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['timeout'])
            
            start = time.time()
            sock.connect((ip, self.config['port']))
            
            # The critical part: Wrap socket with SNI
            ssl_sock = context.wrap_socket(sock, server_hostname=self.config['domain'])
            
            latency = int((time.time() - start) * 1000)
            
            # Clean close
            ssl_sock.close()
            sock.close()
            
            return {
                "ip": ip, 
                "latency": latency, 
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
        except:
            return None
        finally:
            try: sock.close()
            except: pass
