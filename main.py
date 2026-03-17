#!/usr/bin/env python3
import asyncio, ipaddress, sys, csv
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QTextEdit,
    QLabel, QMessageBox, QCheckBox, QScrollArea, QGridLayout
)
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as PDFTable
from docx import Document

TIMEOUT = 1
MAX_CONCURRENT = 1000

# Ports par défaut pour GUI, mais l'utilisateur peut entrer sa plage
COMMON_PORTS = [
    21,22,23,25,53,80,110,143,443,3389,3306,5432,6379,8080,8443
]

SERVICE_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",69:"TFTP",80:"HTTP",110:"POP3",119:"NNTP",
    123:"NTP",137:"NetBIOS",138:"NetBIOS",139:"SMB",
    143:"IMAP",161:"SNMP",179:"BGP",389:"LDAP",443:"HTTPS",
    445:"SMB",465:"SMTPS",500:"ISAKMP",514:"Syslog",515:"Printer",
    520:"RIP",587:"SMTP",636:"LDAPS",989:"FTPS",990:"FTPS",
    1433:"MSSQL",1521:"Oracle",2049:"NFS",2082:"cPanel",2083:"cPanel SSL",
    2181:"Zookeeper",2375:"Docker",2483:"Oracle SSL",3000:"NodeJS",
    3128:"Proxy",3306:"MySQL",3389:"RDP",3690:"SVN",4444:"Metasploit",
    4567:"Rails",5000:"Flask",5432:"PostgreSQL",5601:"Kibana",5672:"RabbitMQ",
    5900:"VNC",5985:"WinRM",5986:"WinRM SSL",6379:"Redis",6667:"IRC",
    7001:"WebLogic",7002:"WebLogic SSL",7077:"Spark",7199:"Cassandra",
    7474:"Neo4j",7777:"Game Server",8000:"HTTP Alt",8080:"HTTP Proxy",
    8443:"HTTPS Alt",9000:"SonarQube",9042:"Cassandra",9092:"Kafka",
    9200:"Elasticsearch",9418:"Git",9999:"Java Debug"
}

def detect_service(port):
    return SERVICE_PORTS.get(port,"Unknown")

# ---------------- Scan asynchrone -----------------
async def scan_port(ip, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_ports(ip, ports):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    async def sem_scan(p):
        async with semaphore:
            return await scan_port(ip, p)
    tasks = [sem_scan(p) for p in ports]
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
        for port in sorted(ports):
            r = await scan_port(ip, port)
            if r:
                results.append({"ip": ip, "port": port, "service": detect_service(port)})
    return results

# ---------------- Export PDF/DOCX/CSV -----------------
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

# ---------------- GUI professionnelle -----------------
class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Audit Tool Ultimate")
        self.resize(700,700)
        layout = QVBoxLayout()

        # Input IP / CIDR
        layout.addWidget(QLabel("Target IP / Network (CIDR):"))
        self.target_input = QLineEdit()
        layout.addWidget(self.target_input)

        # Input ports (plage ou liste)
        layout.addWidget(QLabel("Ports to scan (comma or range, e.g., 22,80,443 or 20-1024):"))
        self.port_input = QLineEdit()
        self.port_input.setText("20-1024")
        layout.addWidget(self.port_input)

        # Export options
        self.pdf_cb = QCheckBox("Generate PDF")
        self.pdf_cb.setChecked(True)
        self.docx_cb = QCheckBox("Generate DOCX")
        self.docx_cb.setChecked(True)
        self.csv_cb = QCheckBox("Generate CSV")
        self.csv_cb.setChecked(True)
        layout.addWidget(self.pdf_cb)
        layout.addWidget(self.docx_cb)
        layout.addWidget(self.csv_cb)

        # Start button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.setLayout(layout)

    def parse_ports(self, text):
        ports = set()
        parts = text.split(",")
        for part in parts:
            if "-" in part:
                start,end = part.split("-")
                ports.update(range(int(start), int(end)+1))
            else:
                ports.add(int(part.strip()))
        return sorted(ports)

    def start_scan(self):
        target = self.target_input.text()
        ports_text = self.port_input.text()
        if not target or not ports_text:
            QMessageBox.warning(self,"Input Error","Enter target IP/network and ports.")
            return
        try:
            ports = self.parse_ports(ports_text)
        except:
            QMessageBox.warning(self,"Input Error","Invalid port format.")
            return

        self.output.clear()
        results = asyncio.run(run_scan(target, ports))
        if not results:
            self.output.append("No open ports found.")
        else:
            for r in results:
                self.output.append(f"{r['ip']}:{r['port']} -> {r['service']}")

            if self.pdf_cb.isChecked(): export_pdf(results)
            if self.docx_cb.isChecked(): export_docx(results)
            if self.csv_cb.isChecked(): export_csv(results)

            self.output.append("Reports generated!")

def main():
    app = QApplication(sys.argv)
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
