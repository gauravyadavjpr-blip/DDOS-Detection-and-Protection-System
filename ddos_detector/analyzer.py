import socket

from scapy.all import IP, TCP, UDP, ICMP


class PacketAnalyzer:
    """Parse and summarize a packet in a UI-friendly structure."""

    def __init__(self):
        self.domain_cache = {}

    def resolve_domain(self, ip):
        if ip in self.domain_cache:
            return self.domain_cache[ip]
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result = hostname
        except Exception:
            result = ""
        self.domain_cache[ip] = result
        return result

    def analyze_packet(self, packet):
        details = {}
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src = ip_layer.src
            dst = ip_layer.dst
            details["src"] = src
            details["dst"] = dst
            details["src_domain"] = self.resolve_domain(src)
            details["dst_domain"] = self.resolve_domain(dst)
        else:
            details["src"] = details["dst"] = "N/A"
            details["src_domain"] = details["dst_domain"] = ""

        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            details["protocol"] = "TCP"
            details["src_port"] = str(tcp.sport)
            details["dst_port"] = str(tcp.dport)
            details["info"] = f"TCP Flags: {tcp.flags}"
        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            details["protocol"] = "UDP"
            details["src_port"] = str(udp.sport)
            details["dst_port"] = str(udp.dport)
            details["info"] = "UDP packet"
        elif packet.haslayer(ICMP):
            icmp = packet.getlayer(ICMP)
            details["protocol"] = "ICMP"
            details["src_port"] = ""
            details["dst_port"] = ""
            details["info"] = f"ICMP Type: {icmp.type}, Code: {icmp.code}"
        else:
            details["protocol"] = packet.lastlayer().name if packet.lastlayer() else "Other"
            details["src_port"] = details["dst_port"] = ""
            details["info"] = packet.summary()

        details["length"] = str(len(packet))
        return details
