import csv
import datetime
import logging
import random
import sys

from PyQt5 import QtWidgets, QtCore
from scapy.all import rdpcap, raw, conf, get_if_list, IP, TCP, UDP, ICMP

from .alerts import AlertManager
from .analyzer import PacketAnalyzer
from .capture import PacketCapture
from .config import ConfigLoader
from .detector import AnomalyDetector
from .mitigation import MitigationEngine
from .threat_intel import ThreatIntelligence
from .ui import AdvancedDashboard, TCPStreamDialog


class RealTimeDDoSMonitor:
    def __init__(self, config_file: str = "config.ini"):
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
        self.config = ConfigLoader(config_file)
        configured_interface = self.config.get("Network", "Interface", fallback="auto").strip()
        self.filter_str = self.config.get("Network", "Filter", fallback=None)
        self.interface = self.resolve_interface(configured_interface)
        self.packet_rate_limit = int(self.config.get("Detection", "RateLimit", fallback="50"))
        self.block_duration = int(self.config.get("Mitigation", "BlockDuration", fallback="600"))
        self.email_alert = self.config.get("Alerts", "EmailAlert", fallback="no")
        self.sms_alert = self.config.get("Alerts", "SMSAlert", fallback="no")
        self.smtp_server = self.config.get("Alerts", "SMTPServer", fallback="")
        self.smtp_port = self.config.get("Alerts", "SMTPPort", fallback="25")
        self.email_from = self.config.get("Alerts", "EmailFrom", fallback="")
        self.email_to = self.config.get("Alerts", "EmailTo", fallback="")
        self.email_user = self.config.get("Alerts", "EmailUser", fallback="")
        self.email_pass = self.config.get("Alerts", "EmailPass", fallback="")
        self.threat_feed_url = self.config.get("ThreatIntel", "FeedURL", fallback="").strip()
        self.update_interval = self.config.get("ThreatIntel", "UpdateInterval", fallback="3600")
        self.refresh_interval = int(self.config.get("GUI", "RefreshInterval", fallback="1000"))

        self.analyzer = PacketAnalyzer()
        self.detector = AnomalyDetector(self.packet_rate_limit)
        self.mitigation = MitigationEngine(chain=self.config.get("Mitigation", "IptablesChain", fallback="INPUT"))
        self.threat_intel = ThreatIntelligence(self.threat_feed_url, int(self.update_interval))
        self.alert_manager = AlertManager(self.email_alert, self.sms_alert,
                                            self.smtp_server, self.smtp_port,
                                            self.email_from, self.email_to,
                                            self.email_user, self.email_pass)

        self.protocol_counts = {}
        self.captured_packets = []
        self.packet_lengths = []

        self.app = QtWidgets.QApplication(sys.argv)
        self.dashboard = AdvancedDashboard(self.refresh_interval, monitor=self)
        self.dashboard.startCaptureRequested.connect(self.start_live_capture)
        self.dashboard.pauseCaptureRequested.connect(self.pause_live_capture)
        self.dashboard.stopCaptureRequested.connect(self.stop_live_capture)
        self.dashboard.openFileRequested.connect(self.open_file_and_analyze)
        self.dashboard.clearTableRequested.connect(self.clear_all)
        self.dashboard.refreshBlockedRequested.connect(self.update_blocked_ips)
        self.dashboard.exportCsvRequested.connect(self.export_table_to_csv)
        self.dashboard.savePcapRequested.connect(self.save_pcap_file)
        self.dashboard.packetDoubleClicked.connect(self.show_packet_details)
        self.dashboard.packet_signal.connect(self.dashboard.add_packet_entry)
        self.dashboard.captureError.connect(self.show_capture_error)

        self.live_capture = None
        self.paused = False
        self.start_live_capture()

        self.chart_timer = QtCore.QTimer()
        self.chart_timer.setInterval(1000)
        self.chart_timer.timeout.connect(self.update_charts)
        self.chart_timer.start()

        self.demo_timer = QtCore.QTimer()
        self.demo_timer.setInterval(1000)
        self.demo_timer.timeout.connect(self.generate_demo_packet)
        self.demo_timer.start()

    def generate_demo_packet(self):
        if not self.captured_packets:
            # The first demo packet may be enough to populate the UI.
            src = random.choice(["203.0.113.10", "198.51.100.22", "10.0.0.5"])
            dst = random.choice(["192.0.2.15", "198.51.100.99", "203.0.113.3"])
            proto = random.choice(["TCP", "UDP", "ICMP"])
            if proto == "TCP":
                packet = IP(src=src, dst=dst) / TCP(sport=50000, dport=80, flags="S")
            elif proto == "UDP":
                packet = IP(src=src, dst=dst) / UDP(sport=50000, dport=53)
            else:
                packet = IP(src=src, dst=dst) / ICMP()
            self.process_packet(packet)
            self.dashboard.statusBar.showMessage("Demo traffic generated.", 1000)

    def process_packet(self, packet):
        try:
            details = self.analyzer.analyze_packet(packet)
            details['time'] = datetime.datetime.now().strftime("%H:%M:%S")
            src_ip = details.get('src', '')
            proto = details.get('protocol', 'Other').upper()
            self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
            self.packet_lengths.append(int(details.get('length', '0')))

            if src_ip:
                if self.threat_intel.is_malicious(src_ip):
                    self.alert_manager.send_alert(f"Known malicious IP detected: {src_ip}")
                    self.mitigation.block_ip(src_ip)
                if self.detector.update_and_check(src_ip):
                    self.alert_manager.send_alert(f"Anomalous traffic from IP: {src_ip}")
                    self.mitigation.block_ip(src_ip)

            self.captured_packets.append(packet)
            self.dashboard.packet_signal.emit(details)
        except Exception as exc:
            logging.error("Error processing packet: %s", exc)

    def start_live_capture(self):
        if self.live_capture is None or not self.live_capture.is_alive():
            self.paused = False
            self.live_capture = PacketCapture(interface=self.interface,
                                               bpf_filter=self.filter_str,
                                               callback=self.process_packet,
                                               error_callback=self.capture_error)
            self.live_capture.start()
            self.dashboard.statusBar.showMessage(
                f"Live capture started on {self.interface_name(self.interface)}.",
                3000,
            )
        else:
            self.dashboard.statusBar.showMessage("Live capture already running.", 3000)

    def pause_live_capture(self):
        if self.live_capture is not None and not self.paused:
            self.live_capture.stop()
            self.paused = True
            self.dashboard.statusBar.showMessage("Live capture paused.", 3000)

    def stop_live_capture(self):
        if self.live_capture is not None:
            self.live_capture.stop()
            self.paused = False
            self.dashboard.statusBar.showMessage("Live capture stopped.", 3000)

    def capture_error(self, message):
        self.dashboard.captureError.emit(message)

    def show_capture_error(self, message):
        logging.error(message)
        self.dashboard.statusBar.showMessage(
            "Capture unavailable. Install Npcap with WinPcap compatibility enabled.",
            10000,
        )

    def open_file_and_analyze(self):
        self.stop_live_capture()
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if filename:
            self.dashboard.statusBar.showMessage(f"Analyzing file: {filename}", 3000)
            try:
                packets = rdpcap(filename)
                for packet in packets:
                    self.process_packet(packet)
                self.dashboard.statusBar.showMessage(f"File analysis complete: {len(packets)} packets", 5000)
            except Exception as exc:
                logging.error("Error reading file: %s", exc)
                self.dashboard.statusBar.showMessage("Error reading PCAP file.", 5000)

    def update_charts(self):
        self.dashboard.update_charts(self.protocol_counts, self.packet_lengths, self.captured_packets, self.analyzer)
        self.update_blocked_ips()

    def update_blocked_ips(self):
        blocked = []
        now = datetime.datetime.now().strftime("%H:%M:%S")
        for ip in sorted(self.mitigation.blocked_ips):
            blocked.append((ip, now))
        self.dashboard.set_blocked_ips(blocked)

    def show_packet_details(self, row):
        try:
            packet = self.captured_packets[row]
            layered_info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i + 32] for i in range(0, len(hex_dump), 32))
            details = layered_info + "\n\nHex Dump:\n" + formatted_hex
            dlg = PacketDetailsTreeDialog(details, packet, self.dashboard)
            dlg.exec_()
            self.dashboard.update_details_panel(row, packet)
        except Exception as exc:
            logging.error("Error showing packet details: %s", exc)

    def clear_all(self):
        self.dashboard.clear_table()
        self.captured_packets = []
        self.packet_lengths = []
        self.protocol_counts.clear()

    def export_table_to_csv(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Export Table to CSV", "", "CSV Files (*.csv)")
        if filepath:
            try:
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    headers = [self.dashboard.packet_table.horizontalHeaderItem(col).text() for col in range(self.dashboard.packet_table.columnCount())]
                    writer.writerow(headers)
                    for row in range(self.dashboard.packet_table.rowCount()):
                        if self.dashboard.packet_table.isRowHidden(row):
                            continue
                        rowdata = []
                        for col in range(self.dashboard.packet_table.columnCount()):
                            item = self.dashboard.packet_table.item(row, col)
                            rowdata.append(item.text() if item else "")
                        writer.writerow(rowdata)
                self.dashboard.statusBar.showMessage(f"Exported table to {filepath}", 3000)
            except Exception as exc:
                self.dashboard.statusBar.showMessage(f"Error exporting CSV: {exc}", 3000)

    def save_pcap_file(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Save PCAP File", "", "PCAP Files (*.pcap)")
        if filepath:
            try:
                from scapy.all import wrpcap
                wrpcap(filepath, self.captured_packets)
                self.dashboard.statusBar.showMessage(f"Saved {len(self.captured_packets)} packets to {filepath}", 3000)
            except Exception as exc:
                self.dashboard.statusBar.showMessage(f"Error saving PCAP: {exc}", 3000)

    def run(self):
        self.dashboard.show()
        sys.exit(self.app.exec_())

    def resolve_interface(self, configured_interface):
        available = get_if_list()
        if not available:
            return configured_interface or "eth0"

        if configured_interface and configured_interface.lower() != "auto":
            if configured_interface in available:
                return configured_interface
            for key, iface in conf.ifaces.items():
                if getattr(iface, "name", "") == configured_interface:
                    return key

        candidates = []
        for key, iface in conf.ifaces.items():
            address = getattr(iface, "ip", "") or ""
            name = getattr(iface, "name", "") or ""
            if not address or address.startswith(("127.", "169.254.")):
                continue
            if "loopback" in name.lower() or "bluetooth" in name.lower():
                continue
            candidates.append((key, name))

        for key, name in candidates:
            if "vmware" not in name.lower() and "virtual" not in name.lower():
                return key
        if candidates:
            return candidates[0][0]

        return available[0]

    def interface_name(self, interface):
        iface = conf.ifaces.get(interface)
        return getattr(iface, "name", interface)

    def stop(self):
        if self.live_capture is not None:
            self.live_capture.stop()


class PacketDetailsTreeDialog(QtWidgets.QDialog):
    def __init__(self, details, packet, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.resize(720, 480)
        layout = QtWidgets.QVBoxLayout(self)
        text = QtWidgets.QTextEdit(self)
        text.setReadOnly(True)
        text.setText(details)
        layout.addWidget(text)
        button = QtWidgets.QPushButton("Close", self)
        button.clicked.connect(self.accept)
        layout.addWidget(button)


def main():
    monitor = RealTimeDDoSMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.stop()


if __name__ == "__main__":
    main()
