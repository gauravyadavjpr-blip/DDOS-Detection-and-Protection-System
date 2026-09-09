import logging
import threading
import time

import requests


class ThreatIntelligence:
    """Threat feed updater and malicious IP membership check."""

    def __init__(self, feed_url: str = "", update_interval: int = 3600):
        self.feed_url = (feed_url or "").strip()
        self.update_interval = int(update_interval or 3600)
        self.malicious_ips = set()
        self.lock = threading.Lock()
        self.running = True
        self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
        self.update_thread.start()

    def update_loop(self):
        while self.running:
            self.update_threats()
            time.sleep(self.update_interval)

    def update_threats(self):
        if not self.feed_url:
            return
        try:
            response = requests.get(self.feed_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    data = data.get("ips", data.get("bad_ips", []))
                if not isinstance(data, list):
                    data = list(data.values()) if isinstance(data, dict) else []
                with self.lock:
                    self.malicious_ips = {str(item) for item in data}
                logging.info("Threat intelligence updated.")
            else:
                logging.warning("Threat intelligence feed returned non-200 status")
        except Exception as exc:
            logging.error("Error updating threat intelligence: %s", exc)

    def is_malicious(self, ip: str) -> bool:
        with self.lock:
            return ip in self.malicious_ips
