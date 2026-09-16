import logging
import threading

from scapy.all import sniff


class PacketCapture(threading.Thread):
    """Scapy-based capture thread with callback support."""

    def __init__(self, interface: str, bpf_filter: str, callback, error_callback=None):
        super().__init__(daemon=True)
        self.interface = interface
        self.bpf_filter = bpf_filter or ""
        self.callback = callback
        self.error_callback = error_callback
        self.stop_event = threading.Event()

    def run(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.packet_handler,
                stop_filter=self.should_stop,
            )
        except Exception as exc:
            message = f"Packet capture failed on {self.interface}: {exc}"
            logging.error(message)
            if self.error_callback:
                self.error_callback(message)

    def packet_handler(self, packet):
        if self.callback:
            self.callback(packet)

    def should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        self.stop_event.set()
