import sys
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QTextEdit, QTableWidget, 
                             QTableWidgetItem, QLineEdit, QFrame, QHeaderView, QMessageBox)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import threading
from queue import Queue, Empty


class ModernFrame(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("""
            ModernFrame {
                background-color: #ffffff;
                border-radius: 12px;
                border: 1px solid #dcdcdc;
                padding: 8px;
            }
        """)


class StopServerThread(QThread):
    finished = pyqtSignal()  

    def __init__(self, server_process):
        super().__init__()
        self.server_process = server_process

    def run(self):
        try:
            if self.server_process:
                self.server_process.terminate()  
                self.server_process.wait(timeout=5)  
        except subprocess.TimeoutExpired:
            self.server_process.kill()  
        self.server_process = None
        self.finished.emit()  


class DHCPServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DHCP Server Management")
        self.setGeometry(100, 100, 1000, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 14px;
                padding: 8px 16px;
                border-radius: 8px;
                border: 1px solid #45a049;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QLabel {
                font-weight: bold;
                font-size: 14px;
                color: #2c3e50;
            }
            QLineEdit {
                padding: 10px;
                border: 1px solid #dcdcdc;
                border-radius: 6px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
            QTextEdit {
                font-family: "Courier New", monospace;
                font-size: 14px;
                background-color: #ffffff;
                border: 1px solid #dcdcdc;
                border-radius: 8px;
            }
            QTableWidget {
                border: 1px solid #dcdcdc;
                background-color: white;
                font-size: 14px;
            }
            QHeaderView::section {
                background-color: #f1f1f1;
                padding: 8px;
                font-weight: bold;
                border: 1px solid #dcdcdc;
            }
        """)

        self.active_leases = {}  

        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        
        status_frame = ModernFrame()
        status_layout = QHBoxLayout(status_frame)
        self.status_label = QLabel("Status: Stopped")
        self.status_label.setStyleSheet("font-size: 16px; color: #e74c3c;")
        self.start_button = QPushButton("Start Server")
        self.start_button.setMinimumWidth(140)
        self.start_button.clicked.connect(self.toggle_server)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.start_button)
        layout.addWidget(status_frame)

        
        config_frame = ModernFrame()
        config_layout = QVBoxLayout(config_frame)
        config_layout.setSpacing(15)

        
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP Range:"))
        self.ip_start = QLineEdit("192.168.1.100")
        self.ip_end = QLineEdit("192.168.1.200")
        ip_layout.addWidget(self.ip_start)
        ip_layout.addWidget(QLabel("to"))
        ip_layout.addWidget(self.ip_end)
        config_layout.addLayout(ip_layout)

        
        subnet_layout = QHBoxLayout()
        subnet_layout.addWidget(QLabel("Subnet Mask:"))
        self.subnet_mask = QLineEdit("255.255.255.0")
        subnet_layout.addWidget(self.subnet_mask)
        config_layout.addLayout(subnet_layout)

        
        settings_layout = QHBoxLayout()
        self.gateway = QLineEdit("192.168.1.1")
        self.dns = QLineEdit("8.8.8.8")
        self.lease_time = QLineEdit("3600")

        for label, widget in [
            ("Gateway:", self.gateway),
            ("DNS:", self.dns),
            ("Lease Time:", self.lease_time)
        ]:
            container = QVBoxLayout()
            container.addWidget(QLabel(label))
            container.addWidget(widget)
            settings_layout.addLayout(container)

        config_layout.addLayout(settings_layout)

        
        save_button = QPushButton("Save Configuration")
        save_button.clicked.connect(self.save_config)
        config_layout.addWidget(save_button, alignment=Qt.AlignRight)

        layout.addWidget(config_frame)

        
        lease_frame = ModernFrame()
        lease_layout = QVBoxLayout(lease_frame)
        self.lease_table = QTableWidget()
        self.lease_table.setColumnCount(4)
        self.lease_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Lease Expiry", "Status"])
        self.lease_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lease_table.setAlternatingRowColors(True)
        lease_layout.addWidget(self.lease_table)
        layout.addWidget(lease_frame)

        
        log_frame = ModernFrame()
        log_layout = QVBoxLayout(log_frame)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_frame)

        
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.update_status)
        self.refresh_timer.start(2000)  

        self.server_process = None
        self.is_running = False
        self.queue = Queue()
        self.thread = None

        
        app = QApplication.instance()
        app.setFont(QFont("Segoe UI", 10))

    def stop_server(self):
        if self.server_process:
            self.log_message("Stopping server...")
            self.start_button.setEnabled(False)  
            self.status_label.setText("Status: Stopping...")
            self.status_label.setStyleSheet("font-weight: bold; color: #e67e22;")

            
            self.stop_thread = StopServerThread(self.server_process)
            self.stop_thread.finished.connect(self.on_server_stopped)
            self.stop_thread.start()

    def on_server_stopped(self):
        self.is_running = False
        self.server_process = None
        self.start_button.setText("Start Server")
        self.start_button.setStyleSheet("")
        self.start_button.setEnabled(True)
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        self.log_message("Server stopped successfully.")

    def closeEvent(self, event):
        if self.is_running:
            reply = QMessageBox.question(self, 'Exit', 
                                        "The server is running. Do you want to stop it and exit?",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.stop_server()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

    def toggle_server(self):
        if not self.is_running:
            try:
                self.server_process = subprocess.Popen(
                    ['sudo', './dhcp_server'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    text=True
                )
                self.thread = threading.Thread(target=self.enqueue_output, args=(self.server_process.stdout, self.queue))
                self.thread.daemon = True
                self.thread.start()

                self.is_running = True
                self.start_button.setText("Stop Server")
                self.start_button.setStyleSheet("""
                    QPushButton {
                        background-color: #e74c3c;
                    }
                    QPushButton:hover {
                        background-color: #c0392b;
                    }
                """)
                self.status_label.setText("Status: Running")
                self.status_label.setStyleSheet("font-size: 16px; color: #27ae60;")
                self.log_message("Server started")
            except Exception as e:
                self.log_message(f"Error starting server: {str(e)}")
        else:
            self.stop_server()

    def enqueue_output(self, out, queue):
        for line in iter(out.readline, ''):
            queue.put(line.strip())
        out.close()

    def save_config(self):
        try:
            new_start = self.ip_start.text()
            new_end = self.ip_end.text()

            
            with open('config.txt', 'w') as f:
                f.write(f"ip_range_start={new_start}\n")
                f.write(f"ip_range_end={new_end}\n")
                f.write(f"lease_duration={self.lease_time.text()}\n")
                f.write(f"gateway={self.gateway.text()}\n")
                f.write(f"dns_server={self.dns.text()}\n")
                f.write(f"subnet_mask={self.subnet_mask.text()}\n")

            
            self.mark_out_of_range_leases(new_start, new_end)

            self.log_message("Configuration saved successfully")
        except Exception as e:
            self.log_message(f"Error saving configuration: {str(e)}")


    def update_status(self):
        try:
            while True:
                try:
                    line = self.queue.get_nowait()
                except Empty:
                    break
                else:
                    self.log_message(line)  
                    if "Sent DHCP ACK to" in line:
                        self.update_lease_table(line)  
        except Exception as e:
            self.log_message(f"Error updating status: {str(e)}")

    


    def update_lease_table(self, lease_info):
        try:
            
            if "Sent DHCP ACK to" in lease_info:
                ip = lease_info.split("Sent DHCP ACK to")[1].strip().split()[0]
                mac = self.extract_mac(lease_info)  
                if ip == "(null)":
                    self.log_message("Received invalid IP in log entry, skipping table update.")
                    return
            else:
                self.log_message(f"Malformed lease info: {lease_info}")
                return

            lease_time = self.lease_time.text()  
            status = "Active"

            
            if mac in self.active_leases:
                old_ip = self.active_leases[mac]
                if old_ip != ip:
                    
                    self.mark_ip_inactive(old_ip)

            
            self.active_leases[mac] = ip

            
            for row in range(self.lease_table.rowCount()):
                if self.lease_table.item(row, 0) and self.lease_table.item(row, 0).text() == ip:
                    self.lease_table.setItem(row, 2, QTableWidgetItem(lease_time))
                    self.lease_table.setItem(row, 3, QTableWidgetItem(status))
                    return

            
            row_count = self.lease_table.rowCount()
            self.lease_table.insertRow(row_count)
            self.lease_table.setItem(row_count, 0, QTableWidgetItem(ip))
            self.lease_table.setItem(row_count, 1, QTableWidgetItem(mac))
            self.lease_table.setItem(row_count, 2, QTableWidgetItem(lease_time))
            self.lease_table.setItem(row_count, 3, QTableWidgetItem(status))

        except Exception as e:
            self.log_message(f"Error updating lease table: {str(e)}")


    def log_message(self, message):
        self.log_text.append(message)

    def mark_out_of_range_leases(self, new_start, new_end):
        try:
            
            new_start_int = self.ip_to_int(new_start)
            new_end_int = self.ip_to_int(new_end)

            
            for row in range(self.lease_table.rowCount()):
                ip_item = self.lease_table.item(row, 0)
                status_item = self.lease_table.item(row, 3)

                if ip_item:
                    ip = ip_item.text()
                    ip_int = self.ip_to_int(ip)

                    
                    if ip_int < new_start_int or ip_int > new_end_int:
                        
                        if status_item:
                            status_item.setText("Inactive")
                        else:
                            self.lease_table.setItem(row, 3, QTableWidgetItem("Inactive"))
        except Exception as e:
            self.log_message(f"Error marking out-of-range leases: {str(e)}")

    def ip_to_int(self, ip):
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


    def mark_ip_inactive(self, ip):
        for row in range(self.lease_table.rowCount()):
            if self.lease_table.item(row, 0) and self.lease_table.item(row, 0).text() == ip:
                self.lease_table.setItem(row, 3, QTableWidgetItem("Inactive"))
                return
    def extract_mac(self, lease_info):
        try:
            if "from client" in lease_info:
                mac = lease_info.split("from client")[1].strip().split()[0]
                return mac
        except IndexError:
            pass
        return "Unknown"  


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DHCPServerGUI()
    window.show()
    sys.exit(app.exec_())
