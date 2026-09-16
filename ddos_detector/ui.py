import csv
import logging
from pathlib import Path

from matplotlib import pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5 import QtWidgets, QtCore, QtGui
from scapy.all import raw


class TCPStreamDialog(QtWidgets.QDialog):
    def __init__(self, conversation_packets, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Follow TCP Stream")
        self.resize(800, 600)
        layout = QtWidgets.QVBoxLayout(self)
        text = QtWidgets.QTextEdit(self)
        text.setReadOnly(True)
        stream_info = "\n".join(packet.summary() for packet in conversation_packets)
        text.setText(stream_info)
        layout.addWidget(text)
        btn = QtWidgets.QPushButton("Close", self)
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)


class PacketDetailsPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        self.details_tabs = QtWidgets.QTabWidget(self)
        self.info_text = QtWidgets.QTextEdit(self)
        self.info_text.setReadOnly(True)
        self.info_text.setStyleSheet("background: #171b24; color: #eaf0ff; font-family: Consolas;")
        self.hex_text = QtWidgets.QTextEdit(self)
        self.hex_text.setReadOnly(True)
        self.hex_text.setStyleSheet("background: #171b24; color: #eaf0ff; font-family: Consolas;")
        self.details_tabs.addTab(self.info_text, "Detailed Info")
        self.details_tabs.addTab(self.hex_text, "Hex Dump")
        layout.addWidget(self.details_tabs)

    def update_details(self, packet):
        try:
            info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i + 32] for i in range(0, len(hex_dump), 32))
            self.info_text.setText(info)
            self.hex_text.setText(formatted_hex)
        except Exception as exc:
            self.info_text.setText(f"Error: {exc}")
            self.hex_text.setText("")


class AdvancedDashboard(QtWidgets.QMainWindow):
    startCaptureRequested = QtCore.pyqtSignal()
    pauseCaptureRequested = QtCore.pyqtSignal()
    stopCaptureRequested = QtCore.pyqtSignal()
    openFileRequested = QtCore.pyqtSignal()
    clearTableRequested = QtCore.pyqtSignal()
    refreshBlockedRequested = QtCore.pyqtSignal()
    exportCsvRequested = QtCore.pyqtSignal()
    savePcapRequested = QtCore.pyqtSignal()
    packetDoubleClicked = QtCore.pyqtSignal(int)
    packet_signal = QtCore.pyqtSignal(dict)
    captureError = QtCore.pyqtSignal(str)

    def __init__(self, refresh_interval: int = 1000, monitor=None):
        super().__init__()
        self.setWindowTitle("Advanced DDoS Detection & Protection System")
        self.resize(1440, 920)
        self.refresh_interval = refresh_interval
        self.monitor = monitor
        self.traffic_data = []
        self.max_data_points = 60
        self.packet_lengths = []
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(
            """
            QMainWindow { background: #101624; color: #dce8ff; }
            QWidget { color: #dce8ff; }
            QToolBar { background: #141b2b; border: none; }
            QToolButton { background: #273355; color: #ffffff; border: 1px solid #42517a; padding: 8px 14px; border-radius: 8px; }
            QToolButton:hover { background: #2e427a; }
            QPushButton { background: #264c9e; color: #fff; border: 1px solid #385baf; border-radius: 6px; padding: 7px 12px; }
            QLineEdit { background: #111827; color: #eef6ff; border: 1px solid #33486e; padding: 6px; border-radius: 4px; }
            QTableWidget { background: #161b2a; color: #dce8ff; gridline-color: #374a68; alternate-background-color: #1d2333; }
            QHeaderView::section { background: #263153; color: #fff; padding: 6px; }
            QTabWidget::pane { background: #111724; border: 1px solid #273250; }
            QTabBar::tab { background: #172036; color: #b0bee5; padding: 10px 14px; }
            QTabBar::tab:selected { background: #223660; color: #fff; }
            QStatusBar { background: #0a0f1d; color: #ceefff; }
            QMenuBar { background: #161b2a; color: #dce8ff; }
            QMenu { background: #1c2333; color: #dce8ff; }
            QMenu::item:selected { background: #273661; }
            """
        )

        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        export_csv = QtWidgets.QAction("Export Table to CSV", self)
        export_csv.triggered.connect(lambda: self.exportCsvRequested.emit())
        save_pcap = QtWidgets.QAction("Save PCAP", self)
        save_pcap.triggered.connect(lambda: self.savePcapRequested.emit())
        reset_stats = QtWidgets.QAction("Reset Stats", self)
        reset_stats.triggered.connect(self.reset_stats)
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(export_csv)
        file_menu.addAction(save_pcap)
        file_menu.addAction(reset_stats)
        file_menu.addAction(exit_action)

        self.tabs = QtWidgets.QTabWidget(self)
        self.setCentralWidget(self.tabs)

        # Live tab.
        self.live_tab = QtWidgets.QWidget()
        live_vlayout = QtWidgets.QVBoxLayout(self.live_tab)

        self.capture_toolbar = QtWidgets.QToolBar("Capture Controls", self)
        self.addToolBar(QtCore.Qt.TopToolBarArea, self.capture_toolbar)

        self.start_btn = QtWidgets.QToolButton(self)
        self.start_btn.setText("Start Capture")
        self.start_btn.clicked.connect(lambda: self.startCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.start_btn)

        self.pause_btn = QtWidgets.QToolButton(self)
        self.pause_btn.setText("Pause Capture")
        self.pause_btn.clicked.connect(lambda: self.pauseCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.pause_btn)

        self.stop_btn = QtWidgets.QToolButton(self)
        self.stop_btn.setText("Stop Capture")
        self.stop_btn.clicked.connect(lambda: self.stopCaptureRequested.emit())
        self.capture_toolbar.addWidget(self.stop_btn)

        self.open_btn = QtWidgets.QToolButton(self)
        self.open_btn.setText("Open PCAP File")
        self.open_btn.clicked.connect(lambda: self.openFileRequested.emit())
        self.capture_toolbar.addWidget(self.open_btn)

        self.clear_btn = QtWidgets.QToolButton(self)
        self.clear_btn.setText("Clear Table")
        self.clear_btn.clicked.connect(lambda: self.clearTableRequested.emit())
        self.capture_toolbar.addWidget(self.clear_btn)

        self.refresh_blocked_btn = QtWidgets.QToolButton(self)
        self.refresh_blocked_btn.setText("Refresh Blocked IPs")
        self.refresh_blocked_btn.clicked.connect(lambda: self.refreshBlockedRequested.emit())
        self.capture_toolbar.addWidget(self.refresh_blocked_btn)

        filter_layout = QtWidgets.QHBoxLayout()
        self.filter_input = QtWidgets.QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter filter text (IP, protocol, etc.)")
        self.filter_btn = QtWidgets.QPushButton("Apply Filter", self)
        self.filter_btn.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_btn)
        live_vlayout.addLayout(filter_layout)

        v_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        h_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.packet_table = QtWidgets.QTableWidget()
        self.packet_table.setColumnCount(10)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Src IP", "Src Domain", "Dst IP", "Dst Domain",
            "Src Port", "Dst Port", "Protocol", "Length", "Info"
        ])
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.packet_context_menu)
        self.packet_table.itemSelectionChanged.connect(self.handle_packet_selection)
        self.packet_table.itemDoubleClicked.connect(lambda item: self.packetDoubleClicked.emit(item.row()))
        h_splitter.addWidget(self.packet_table)

        self.blocked_table = QtWidgets.QTableWidget()
        self.blocked_table.setColumnCount(2)
        self.blocked_table.setHorizontalHeaderLabels(["Blocked IP", "Blocked Since"])
        h_splitter.addWidget(self.blocked_table)
        h_splitter.setSizes([900, 400])
        v_splitter.addWidget(h_splitter)

        self.details_panel = PacketDetailsPanel(self)
        v_splitter.addWidget(self.details_panel)
        v_splitter.setStretchFactor(0, 3)
        v_splitter.setStretchFactor(1, 1)
        live_vlayout.addWidget(v_splitter)
        self.tabs.addTab(self.live_tab, "Live Capture")

        # Statistics tab.
        self.stats_tab = QtWidgets.QWidget()
        stats_layout = QtWidgets.QVBoxLayout(self.stats_tab)
        self.charts_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.traffic_fig = plt.figure(figsize=(5, 4), dpi=100)
        self.traffic_canvas = FigureCanvas(self.traffic_fig)
        self.traffic_ax = self.traffic_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.traffic_canvas)

        self.pie_fig = plt.figure(figsize=(5, 4), dpi=100)
        self.pie_canvas = FigureCanvas(self.pie_fig)
        self.pie_ax = self.pie_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.pie_canvas)

        self.hist_fig = plt.figure(figsize=(5, 4), dpi=100)
        self.hist_canvas = FigureCanvas(self.hist_fig)
        self.hist_ax = self.hist_fig.add_subplot(111)
        self.charts_splitter.addWidget(self.hist_canvas)
        self.charts_splitter.setSizes([500, 500, 500])
        stats_layout.addWidget(self.charts_splitter)
        self.tabs.addTab(self.stats_tab, "Statistics")

        # Conversation tab.
        self.conv_tab = QtWidgets.QWidget()
        conv_layout = QtWidgets.QVBoxLayout(self.conv_tab)
        self.conv_table = QtWidgets.QTableWidget()
        self.conv_table.setColumnCount(4)
        self.conv_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Protocol", "Packet Count"])
        conv_layout.addWidget(self.conv_table)
        self.tabs.addTab(self.conv_tab, "Conversation View")

        self.statusBar = QtWidgets.QStatusBar(self)
        self.setStatusBar(self.statusBar)

    def handle_packet_selection(self):
        selected_items = self.packet_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            details = {}
            for col in range(self.packet_table.columnCount()):
                header = self.packet_table.horizontalHeaderItem(col).text()
                item = self.packet_table.item(row, col)
                details[header] = item.text() if item else ""
            self.details_panel.info_text.setText("\n".join(f"{k}: {v}" for k, v in details.items()))
            self.details_panel.hex_text.setText("Hex dump not available from table data")

    def packet_context_menu(self, pos):
        index = self.packet_table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        proto = self.packet_table.item(row, 7).text().upper()
        menu = QtWidgets.QMenu(self)
        if proto == "TCP":
            follow_action = QtWidgets.QAction("Follow TCP Stream", self)
            follow_action.triggered.connect(lambda: self.follow_tcp_stream(row))
            menu.addAction(follow_action)
        menu.exec_(self.packet_table.viewport().mapToGlobal(pos))

    def follow_tcp_stream(self, row):
        src = self.packet_table.item(row, 1).text()
        dst = self.packet_table.item(row, 3).text()
        proto = self.packet_table.item(row, 7).text()
        conv_packets = []
        if self.monitor is not None:
            for packet in self.monitor.captured_packets:
                details = self.monitor.analyzer.analyze_packet(packet)
                if (details.get('src') == src and details.get('dst') == dst and details.get('protocol') == proto):
                    conv_packets.append(packet)
        dlg = TCPStreamDialog(conv_packets, self)
        dlg.exec_()

    def apply_filter(self):
        text = self.filter_input.text().lower().strip()
        for row in range(self.packet_table.rowCount()):
            hide = True
            for col in range(self.packet_table.columnCount()):
                item = self.packet_table.item(row, col)
                if item and text in item.text().lower():
                    hide = False
                    break
            self.packet_table.setRowHidden(row, hide)
        self.statusBar.showMessage("Filter applied.", 3000)

    def clear_table(self):
        self.packet_table.setRowCount(0)
        self.statusBar.showMessage("Packet table cleared.", 3000)

    def add_packet_entry(self, packet_info):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        values = [
            packet_info.get('time', ''), packet_info.get('src', ''), packet_info.get('src_domain', ''),
            packet_info.get('dst', ''), packet_info.get('dst_domain', ''), packet_info.get('src_port', ''),
            packet_info.get('dst_port', ''), packet_info.get('protocol', ''), packet_info.get('length', ''),
            packet_info.get('info', '')
        ]
        for col, val in enumerate(values):
            item = QtWidgets.QTableWidgetItem(val)
            self.packet_table.setItem(row, col, item)

        proto = packet_info.get('protocol', '').upper()
        color = {
            'TCP': QtGui.QColor(70, 130, 180),
            'UDP': QtGui.QColor(60, 179, 113),
            'ICMP': QtGui.QColor(255, 165, 0),
        }.get(proto, QtGui.QColor(169, 169, 169))
        for col in range(self.packet_table.columnCount()):
            self.packet_table.item(row, col).setBackground(color)

        self.traffic_data.append(1)
        if len(self.traffic_data) > self.max_data_points:
            self.traffic_data.pop(0)

    def update_charts(self, protocol_counts, packet_lengths, captured_packets, analyzer):
        self.traffic_ax.clear()
        self.traffic_ax.plot(self.traffic_data, color='cyan')
        self.traffic_ax.set_title("Traffic Volume (packets/sec)", color="#ffffff")
        self.traffic_ax.tick_params(colors="#ffffff")
        self.traffic_canvas.draw()

        self.pie_ax.clear()
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())
        if sizes and sum(sizes) > 0:
            self.pie_ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, textprops={'color': 'w'})
        self.pie_ax.set_title("Protocol Breakdown", color="#ffffff")
        self.pie_canvas.draw()

        self.hist_ax.clear()
        if packet_lengths:
            self.hist_ax.hist(packet_lengths, bins=20, color='magenta')
            self.hist_ax.set_title("Packet Length Distribution", color="#ffffff")
            self.hist_ax.tick_params(colors="#ffffff")
        self.hist_canvas.draw()
        self.update_conversation_view(captured_packets, analyzer)

    def update_conversation_view(self, captured_packets, analyzer):
        conv_dict = {}
        for packet in captured_packets:
            details = analyzer.analyze_packet(packet)
            key = (details.get('src', ''), details.get('dst', ''), details.get('protocol', ''))
            conv_dict[key] = conv_dict.get(key, 0) + 1
        self.conv_table.setRowCount(0)
        for (src, dst, proto), count in conv_dict.items():
            row = self.conv_table.rowCount()
            self.conv_table.insertRow(row)
            self.conv_table.setItem(row, 0, QtWidgets.QTableWidgetItem(src))
            self.conv_table.setItem(row, 1, QtWidgets.QTableWidgetItem(dst))
            self.conv_table.setItem(row, 2, QtWidgets.QTableWidgetItem(proto))
            self.conv_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(count)))
        self.conv_table.resizeColumnsToContents()

    def set_blocked_ips(self, ips):
        self.blocked_table.setRowCount(0)
        for ip, ts in ips:
            row = self.blocked_table.rowCount()
            self.blocked_table.insertRow(row)
            self.blocked_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ip))
            self.blocked_table.setItem(row, 1, QtWidgets.QTableWidgetItem(ts))
        self.blocked_table.resizeColumnsToContents()

    def reset_stats(self):
        self.traffic_data = []
        self.statusBar.showMessage("Statistics reset.", 3000)

    def export_table_csv(self):
        filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Export Table to CSV", "", "CSV Files (*.csv)")
        if not filepath:
            return
        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                headers = [self.packet_table.horizontalHeaderItem(col).text() for col in range(self.packet_table.columnCount())]
                writer.writerow(headers)
                for row in range(self.packet_table.rowCount()):
                    if self.packet_table.isRowHidden(row):
                        continue
                    rowdata = []
                    for col in range(self.packet_table.columnCount()):
                        item = self.packet_table.item(row, col)
                        rowdata.append(item.text() if item else "")
                    writer.writerow(rowdata)
            self.statusBar.showMessage(f"Exported table to {filepath}", 3000)
        except Exception as exc:
            self.statusBar.showMessage(f"Error exporting CSV: {exc}", 3000)

    def save_pcap(self, packets=None, filepath=None):
        from scapy.all import wrpcap
        try:
            if filepath is None:
                filepath, _ = QtWidgets.QFileDialog.getSaveFileName(None, "Save PCAP File", "", "PCAP Files (*.pcap)")
            if not filepath:
                return
            if packets is None:
                packets = getattr(self, "packets", [])
            wrpcap(filepath, packets)
            self.statusBar.showMessage(f"Saved {len(packets)} packets to {filepath}", 3000)
        except Exception as exc:
            self.statusBar.showMessage(f"Error saving PCAP: {exc}", 3000)

    def update_details_panel(self, row, packet):
        try:
            info = packet.show(dump=True)
            hex_dump = raw(packet).hex()
            formatted_hex = "\n".join(hex_dump[i:i + 32] for i in range(0, len(hex_dump), 32))
            self.details_panel.info_text.setText(info)
            self.details_panel.hex_text.setText(formatted_hex)
        except Exception as exc:
            self.details_panel.info_text.setText(f"Error: {exc}")
            self.details_panel.hex_text.setText("")
