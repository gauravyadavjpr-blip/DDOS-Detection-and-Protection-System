import threading
import time


class AnomalyDetector:
    """Threshold-based per-source packet-rate anomaly detector."""

    def __init__(self, rate_limit: int = 50):
        self.rate_limit = int(rate_limit)
        self.ip_counters = {}
        self.lock = threading.Lock()

    def update_and_check(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            if ip not in self.ip_counters:
                self.ip_counters[ip] = [1, now]
                return False

            count, last = self.ip_counters[ip]
            if now - last > 1:
                self.ip_counters[ip] = [1, now]
                return False

            count += 1
            self.ip_counters[ip] = [count, last]
            return count > self.rate_limit
