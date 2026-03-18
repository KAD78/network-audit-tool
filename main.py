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


"""

#!/usr/bin/env python3
import asyncio, ipaddress, sys, csv, socket

# ===== GUI DETECTION =====
GUI_AVAILABLE = True
try:
    from PyQt6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit,
        QTextEdit, QLabel, QMessageBox, QCheckBox, QProgressBar
    )
except:
    GUI_AVAILABLE = False

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as PDFTable
from docx import Document

TIMEOUT = 1
MAX_CONCURRENT = 800

# ===== SERVICES =====
SERVICE_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    6379:"Redis",8080:"HTTP Alt",8443:"HTTPS Alt"
}

def detect_service(port):
    return SERVICE_PORTS.get(port,"Unknown")

# ===== BANNER GRABBING =====
async def grab_banner(ip, port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=TIMEOUT
        )

        # HTTP
        if port in [80,8080,8000]:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=TIMEOUT)
        writer.close()
        await writer.wait_closed()

        return data.decode(errors="ignore").strip().split("\n")[0][:100]
    except:
        return ""

# ===== SCAN =====
async def scan_port(ip, port, sem, progress_cb=None):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()

            banner = await grab_banner(ip, port)

            if progress_cb:
                progress_cb()

            return {
                "ip": ip,
                "port": port,
                "service": detect_service(port),
                "banner": banner
            }
        except:
            if progress_cb:
                progress_cb()
            return None

async def run_scan(target, ports, progress_cb=None):
    ips = expand_targets(target)
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(scan_port(ip, port, sem, progress_cb))

    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

# ===== UTILS =====
def expand_targets(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return [target]

def parse_ports(text):
    ports = set()
    for part in text.split(","):
        if "-" in part:
            start,end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)

# ===== EXPORT =====
def export_csv(results):
    with open("scan.csv","w",newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","port","service","banner"])
        writer.writeheader()
        writer.writerows(results)

def export_pdf(results):
    data = [["IP","Port","Service","Banner"]]
    for r in results:
        data.append([r["ip"],str(r["port"]),r["service"],r["banner"]])
    pdf = SimpleDocTemplate("scan.pdf", pagesize=letter)
    pdf.build([PDFTable(data)])

def export_docx(results):
    doc = Document()
    doc.add_heading("Scan Report",0)
    table = doc.add_table(rows=1, cols=4)
    hdr = table.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text, hdr[3].text = "IP","Port","Service","Banner"
    for r in results:
        row = table.add_row().cells
        row[0].text = r["ip"]
        row[1].text = str(r["port"])
        row[2].text = r["service"]
        row[3].text = r["banner"]
    doc.save("scan.docx")

# ===== CLI =====
def run_cli():
    target = input("Target: ")
    ports = parse_ports(input("Ports: "))

    total = len(ports) * len(expand_targets(target))
    done = 0

    def progress():
        nonlocal done
        done += 1
        print(f"\rProgress: {done}/{total}", end="")

    results = asyncio.run(run_scan(target, ports, progress))

    print("\n\nResults:")
    for r in results:
        print(f"{r['ip']}:{r['port']} -> {r['service']} | {r['banner']}")

    export_csv(results)
    export_pdf(results)
    export_docx(results)

    print("\nReports generated!")

# ===== GUI =====
if GUI_AVAILABLE:

    class ScannerGUI(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Network Audit PRO")
            layout = QVBoxLayout()

            self.target = QLineEdit()
            self.target.setPlaceholderText("IP / CIDR")

            self.ports = QLineEdit("20-1024")

            self.progress = QProgressBar()

            self.output = QTextEdit()

            btn = QPushButton("Start Scan")
            btn.clicked.connect(self.start_scan)

            layout.addWidget(self.target)
            layout.addWidget(self.ports)
            layout.addWidget(self.progress)
            layout.addWidget(btn)
            layout.addWidget(self.output)

            self.setLayout(layout)

        def start_scan(self):
            target = self.target.text()
            ports = parse_ports(self.ports.text())

            total = len(ports) * len(expand_targets(target))
            done = 0

            def progress():
                nonlocal done
                done += 1
                percent = int((done/total)*100)
                self.progress.setValue(percent)

            results = asyncio.run(run_scan(target, ports, progress))

            for r in results:
                self.output.append(f"{r['ip']}:{r['port']} -> {r['service']} | {r['banner']}")

            export_csv(results)
            export_pdf(results)
            export_docx(results)

# ===== ENTRY =====
if __name__ == "__main__":
    if GUI_AVAILABLE:
        try:
            app = QApplication(sys.argv)
            win = ScannerGUI()
            win.show()
            sys.exit(app.exec())
        except:
            run_cli()
    else:
        run_cli()

"""







"""
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


"""





"""
#!/usr/bin/env python3
import asyncio, ipaddress, sys, csv, os

# ===== GUI DETECTION =====
GUI_AVAILABLE = True
try:
    from PyQt6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit,
        QTextEdit, QLabel, QMessageBox, QCheckBox, QFileDialog
    )
except:
    GUI_AVAILABLE = False

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table as PDFTable
from docx import Document

# ===== CONFIG =====
TIMEOUT = 1
MAX_CONCURRENT = 500
ULTRA_CONCURRENT = 1500  # mode rapide

SERVICE_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    6379:"Redis",8080:"HTTP Alt",8443:"HTTPS Alt"
}

def detect_service(port):
    return SERVICE_PORTS.get(port,"Unknown")

# ===== UTILS =====
def expand_targets(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except:
        return [target]

def parse_ports(text):
    ports = set()
    for part in text.split(","):
        if "-" in part:
            start,end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)

# ===== SCAN =====
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

async def run_scan(target, ports, ultra=False):
    ips = expand_targets(target)
    concurrency = ULTRA_CONCURRENT if ultra else MAX_CONCURRENT
    sem = asyncio.Semaphore(concurrency)

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(scan_port(ip, port, sem))

    results = await asyncio.gather(*tasks)

    final = []
    i = 0
    for ip in ips:
        for port in ports:
            if results[i]:
                final.append({
                    "ip": ip,
                    "port": port,
                    "service": detect_service(port)
                })
            i += 1

    return final

# ===== EXPORT =====
def export_docx(results, folder):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "scan_report.docx")

    doc = Document()
    doc.add_heading("Network Scan Report", 0)
    doc.add_paragraph(f"Total results: {len(results)}\n")

    table = doc.add_table(rows=1, cols=3)
    hdr = table.rows[0].cells
    hdr[0].text = "IP"
    hdr[1].text = "Port"
    hdr[2].text = "Service"

    for r in results:
        row = table.add_row().cells
        row[0].text = r["ip"]
        row[1].text = str(r["port"])
        row[2].text = r["service"]

    doc.save(path)
    return path

def export_csv(results):
    with open("scan.csv","w",newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","port","service"])
        writer.writeheader()
        writer.writerows(results)

# ===== CLI =====
def run_cli():
    print("\n=== Network Audit Tool ===\n")

    target = input("Target IP / CIDR: ")
    ports = parse_ports(input("Ports: "))
    ultra = input("Ultra fast mode? (y/n): ").lower() == "y"
    folder = input("DOCX output folder: ")

    print("\nScanning...\n")
    results = asyncio.run(run_scan(target, ports, ultra))

    if not results:
        print("No open ports found.")
    else:
        print("\n=== RESULTS ===\n")
        for r in results:
            print(f"[+] {r['ip']}:{r['port']} → {r['service']}")

        path = export_docx(results, folder)
        export_csv(results)

        print(f"\nSaved DOCX: {path}")
        print("Saved CSV: scan.csv")

# ===== GUI =====
if GUI_AVAILABLE:

    class ScannerGUI(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Network Audit Tool")
            layout = QVBoxLayout()

            self.target = QLineEdit()
            self.target.setPlaceholderText("Target IP / CIDR")

            self.ports = QLineEdit("20-1024")

            self.ultra = QCheckBox("Ultra Fast Mode")

            self.folder_btn = QPushButton("Select DOCX Folder")
            self.folder_btn.clicked.connect(self.select_folder)
            self.folder_path = ""

            self.output = QTextEdit()

            btn = QPushButton("Start Scan")
            btn.clicked.connect(self.start_scan)

            layout.addWidget(QLabel("Target:"))
            layout.addWidget(self.target)

            layout.addWidget(QLabel("Ports:"))
            layout.addWidget(self.ports)

            layout.addWidget(self.ultra)
            layout.addWidget(self.folder_btn)
            layout.addWidget(btn)
            layout.addWidget(self.output)

            self.setLayout(layout)

        def select_folder(self):
            self.folder_path = QFileDialog.getExistingDirectory(self, "Select Folder")

        def start_scan(self):
            target = self.target.text()
            ports = parse_ports(self.ports.text())
            ultra = self.ultra.isChecked()

            self.output.clear()
            results = asyncio.run(run_scan(target, ports, ultra))

            if not results:
                self.output.append("No open ports found.")
                return

            self.output.append("=== RESULTS ===\n")

            for r in results:
                self.output.append(f"[+] {r['ip']}:{r['port']} → {r['service']}")

            folder = self.folder_path if self.folder_path else "."
            path = export_docx(results, folder)
            export_csv(results)

            self.output.append(f"\nDOCX saved: {path}")
            self.output.append("CSV saved: scan.csv")

# ===== ENTRY =====
if __name__ == "__main__":
    if GUI_AVAILABLE:
        try:
            app = QApplication(sys.argv)
            win = ScannerGUI()
            win.show()
            sys.exit(app.exec())
        except:
            run_cli()
    else:
        run_cli()

"""      
