import logging
import subprocess
import threading


class MitigationEngine:
    """Per-IP blocking engine using iptables for Linux systems."""

    def __init__(self, chain: str = "INPUT"):
        self.chain = chain
        self.blocked_ips = set()
        self.lock = threading.Lock()

    def block_ip(self, ip: str):
        with self.lock:
            if ip in self.blocked_ips:
                return
            try:
                subprocess.check_call(["sudo", "iptables", "-A", self.chain, "-s", ip, "-j", "DROP"])
                self.blocked_ips.add(ip)
                logging.info("Blocked IP: %s", ip)
            except Exception as exc:
                logging.error("Error blocking IP %s: %s", ip, exc)

    def unblock_ip(self, ip: str):
        with self.lock:
            if ip not in self.blocked_ips:
                return
            try:
                subprocess.check_call(["sudo", "iptables", "-D", self.chain, "-s", ip, "-j", "DROP"])
                self.blocked_ips.remove(ip)
                logging.info("Unblocked IP: %s", ip)
            except Exception as exc:
                logging.error("Error unblocking IP %s: %s", ip, exc)
