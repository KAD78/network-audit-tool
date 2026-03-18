#!/usr/bin/env python3
import asyncio, ipaddress, sys, csv, os

# ===== Détection PyQt6 =====
GUI_AVAILABLE = True
try:
    from PyQt6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit,
        QTextEdit, QLabel, QMessageBox, QCheckBox
    )
except:
    GUI_AVAILABLE = False

# ===== Export libs =====
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as PDFTable
from docx import Document

TIMEOUT = 1
MAX_CONCURRENT = 500

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,3389,3306,5432,6379,8080,8443]

SERVICE_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    6379:"Redis",8080:"HTTP Alt",8443:"HTTPS Alt"
}

def detect_service(port):
    return SERVICE_PORTS.get(port,"Unknown")

# ===== Scanner =====
async def scan_port(ip, port, sem):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def scan_ports(ip, ports):
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [scan_port(ip, p, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p]

def expand_targets(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return [target]

async def run_scan(target, ports):
    ips = expand_targets(target)
    results = []
    for ip in ips:
        open_ports = await scan_ports(ip, ports)
        for port in open_ports:
            results.append({
                "ip": ip,
                "port": port,
                "service": detect_service(port)
            })
    return results

# ===== Export =====
def export_pdf(results, filename="scan_report.pdf"):
    data = [["IP","Port","Service"]]
    for r in results:
        data.append([r["ip"], str(r["port"]), r["service"]])
    pdf = SimpleDocTemplate(filename, pagesize=letter)
    table = PDFTable(data)
    pdf.build([table])

def export_docx(results, filename="scan_report.docx"):
    doc = Document()
    doc.add_heading("Network Scan Report",0)
    table = doc.add_table(rows=1, cols=3)
    hdr = table.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text = "IP","Port","Service"
    for r in results:
        row = table.add_row().cells
        row[0].text = r["ip"]
        row[1].text = str(r["port"])
        row[2].text = r["service"]
    doc.save(filename)

def export_csv(results, filename="scan_report.csv"):
    with open(filename,"w",newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","port","service"])
        writer.writeheader()
        writer.writerows(results)

# ===== CLI MODE (Termux compatible) =====
def run_cli():
    print("\n=== Network Audit Tool (CLI Mode) ===\n")

    target = input("Target IP / CIDR: ")
    ports_input = input("Ports (ex: 22,80 or 20-1024): ")

    def parse_ports(text):
        ports = set()
        for part in text.split(","):
            if "-" in part:
                start,end = part.split("-")
                ports.update(range(int(start), int(end)+1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    ports = parse_ports(ports_input)

    print("\nScanning...\n")
    results = asyncio.run(run_scan(target, ports))

    if not results:
        print("No open ports found.")
    else:
        for r in results:
            print(f"{r['ip']}:{r['port']} -> {r['service']}")

        export_pdf(results)
        export_docx(results)
        export_csv(results)

        print("\nReports generated!")

# ===== GUI MODE =====
if GUI_AVAILABLE:

    class ScannerGUI(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Network Audit Tool Ultimate")
            self.resize(600,600)
            layout = QVBoxLayout()

            layout.addWidget(QLabel("Target IP / CIDR:"))
            self.target_input = QLineEdit()
            layout.addWidget(self.target_input)

            layout.addWidget(QLabel("Ports (22,80 or 20-1024):"))
            self.port_input = QLineEdit()
            self.port_input.setText("20-1024")
            layout.addWidget(self.port_input)

            self.pdf_cb = QCheckBox("PDF")
            self.docx_cb = QCheckBox("DOCX")
            self.csv_cb = QCheckBox("CSV")
            self.pdf_cb.setChecked(True)
            self.docx_cb.setChecked(True)
            self.csv_cb.setChecked(True)

            layout.addWidget(self.pdf_cb)
            layout.addWidget(self.docx_cb)
            layout.addWidget(self.csv_cb)

            self.scan_btn = QPushButton("Start Scan")
            self.scan_btn.clicked.connect(self.start_scan)
            layout.addWidget(self.scan_btn)

            self.output = QTextEdit()
            layout.addWidget(self.output)

            self.setLayout(layout)

        def parse_ports(self, text):
            ports = set()
            for part in text.split(","):
                if "-" in part:
                    start,end = part.split("-")
                    ports.update(range(int(start), int(end)+1))
                else:
                    ports.add(int(part.strip()))
            return sorted(ports)

        def start_scan(self):
            target = self.target_input.text()
            ports = self.parse_ports(self.port_input.text())

            self.output.clear()
            results = asyncio.run(run_scan(target, ports))

            for r in results:
                self.output.append(f"{r['ip']}:{r['port']} -> {r['service']}")

            if self.pdf_cb.isChecked(): export_pdf(results)
            if self.docx_cb.isChecked(): export_docx(results)
            if self.csv_cb.isChecked(): export_csv(results)

            self.output.append("\nDone!")

# ===== ENTRY POINT =====
if __name__ == "__main__":
    if GUI_AVAILABLE:
        try:
            app = QApplication(sys.argv)
            window = ScannerGUI()
            window.show()
            sys.exit(app.exec())
        except:
            print("GUI failed → switching to CLI mode")
            run_cli()
    else:
        run_cli()
