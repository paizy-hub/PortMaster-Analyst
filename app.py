import io
import socket
import threading
import time
import json
from datetime import datetime
from collections import deque
from flask import Flask, request, jsonify, render_template, send_file
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle

app = Flask(__name__, static_folder='static')

# -----------------------------
# DATA PORT DAN RISK INFO
# -----------------------------
PORT_RISK_INFO = {
    21: {"name": "FTP", "risk_level": "High", "description": "File Transfer Protocol rentan brute force.", "recommendations": "Gunakan SFTP atau FTPS."},
    22: {"name": "SSH", "risk_level": "Medium", "description": "Akses shell terenkripsi.", "recommendations": "Gunakan key authentication."},
    23: {"name": "Telnet", "risk_level": "Critical", "description": "Data dikirim tanpa enkripsi.", "recommendations": "Gunakan SSH."},
    25: {"name": "SMTP", "risk_level": "Medium", "description": "Dapat digunakan spam relay.", "recommendations": "Gunakan SMTP AUTH."},
    53: {"name": "DNS", "risk_level": "Medium", "description": "Rentan cache poisoning.", "recommendations": "Gunakan DNSSEC."},
    80: {"name": "HTTP", "risk_level": "High", "description": "Tidak terenkripsi.", "recommendations": "Gunakan HTTPS."},
    110: {"name": "POP3", "risk_level": "High", "description": "Kredensial dikirim tanpa enkripsi.", "recommendations": "Gunakan POP3S."},
    135: {"name": "RPC", "risk_level": "High", "description": "Sering dieksploitasi.", "recommendations": "Blokir port ini."},
    139: {"name": "NetBIOS", "risk_level": "High", "description": "Rentan serangan file sharing.", "recommendations": "Blokir port eksternal."},
    143: {"name": "IMAP", "risk_level": "High", "description": "Email tanpa enkripsi.", "recommendations": "Gunakan IMAPS."},
    443: {"name": "HTTPS", "risk_level": "Low", "description": "Sudah terenkripsi.", "recommendations": "Gunakan TLS terbaru."},
    445: {"name": "SMB", "risk_level": "Critical", "description": "Rentan ransomware.", "recommendations": "Update patch rutin."},
    993: {"name": "IMAPS", "risk_level": "Low", "description": "Email terenkripsi.", "recommendations": "SSL/TLS aman."},
    995: {"name": "POP3S", "risk_level": "Low", "description": "Email terenkripsi.", "recommendations": "SSL/TLS aman."},
    1723: {"name": "PPTP", "risk_level": "High", "description": "VPN lemah.", "recommendations": "Gunakan OpenVPN."},
    3306: {"name": "MySQL", "risk_level": "High", "description": "Database rentan.", "recommendations": "Aktifkan SSL."},
    3389: {"name": "RDP", "risk_level": "Critical", "description": "Target ransomware.", "recommendations": "Gunakan VPN dan 2FA."},
    5900: {"name": "VNC", "risk_level": "Critical", "description": "Tanpa enkripsi kuat.", "recommendations": "Gunakan VPN."},
    8080: {"name": "HTTP Alt", "risk_level": "High", "description": "Proxy server tanpa enkripsi.", "recommendations": "Gunakan HTTPS."}
}

def get_port_risk_info(port):
    return PORT_RISK_INFO.get(port, {
        "name": "Unknown",
        "risk_level": "Unknown",
        "description": "Informasi tidak tersedia.",
        "recommendations": "Lakukan penelitian lebih lanjut."
    })

# -----------------------------
# GLOBAL VAR UNTUK TRACKING
# -----------------------------
scan_results = {}
scan_status = {}

# -----------------------------
# PORT SCANNER CLASS
# -----------------------------
class PortScanner:
    def __init__(self, target, algorithm='bfs', common_ports_first=True, max_threads=100, scan_id=None, port_range=None):
        self.target = target
        self.algorithm = algorithm.lower()
        self.common_ports_first = common_ports_first
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.active_threads = 0
        self.thread_semaphore = threading.Semaphore(max_threads)
        self.scan_id = scan_id
        self.port_range = port_range if port_range else (1, 1024)
        self.common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]

        # filter hanya yang masuk range
        if port_range:
            self.common_ports = [p for p in self.common_ports if port_range[0] <= p <= port_range[1]]

    def scan_port(self, port):
        try:
            with self.thread_semaphore:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    with self.lock:
                        self.open_ports.append((port, service))
                        if self.scan_id:
                            info = get_port_risk_info(port)
                            scan_results[self.scan_id]['open_ports'].append({
                                'port': port,
                                'service': service,
                                'risk_level': info['risk_level'],
                                'risk_description': info['description'],
                                'recommendations': info['recommendations']
                            })
                s.close()
            if self.scan_id:
                scan_results[self.scan_id]['progress'] += 1
        except:
            pass

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def bfs_scan(self):
        queue = deque()
        visited = set()

        if self.common_ports_first:
            for port in self.common_ports:
                queue.append(port)
                visited.add(port)

        for port in range(self.port_range[0], self.port_range[1]+1):
            if port not in visited:
                queue.append(port)
                visited.add(port)

        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = len(queue)
        
        threads = []
        while queue:
            port = queue.popleft()
            while threading.active_count() > self.max_threads:
                time.sleep(0.1)
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed:.2f}"

    def dfs_scan(self):
        stack = []

        if self.common_ports_first:
            for port in reversed(self.common_ports):
                stack.append(port)

        for port in range(self.port_range[1], self.port_range[0]-1, -1):
            if port not in stack:
                stack.append(port)

        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = len(stack)
        
        threads = []
        while stack:
            port = stack.pop()
            while threading.active_count() > self.max_threads:
                time.sleep(0.1)
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed:.2f}"

    def run(self):
        start_time = time.time()
        if self.scan_id:
            scan_results[self.scan_id] = {
                'target': self.target,
                'algorithm': self.algorithm.upper(),
                'common_ports_first': self.common_ports_first,
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'start_timestamp': start_time,
                'open_ports': [],
                'progress': 0,
                'total_ports': 0
            }
            scan_status[self.scan_id] = "running"

        if self.algorithm == 'bfs':
            self.bfs_scan()
        else:
            self.dfs_scan()

# -----------------------------
# ROUTES
# -----------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    algorithm = data.get('algorithm', 'bfs')
    common_ports_first = data.get('common_ports_first', True)
    max_threads = int(data.get('max_threads', 100))
    port_range_start = int(data.get('port_range_start', 1))
    port_range_end = int(data.get('port_range_end', 1024))
    port_range = (port_range_start, port_range_end)

    scan_id = f"{target}_{int(time.time())}"
    scanner = PortScanner(
        target=target,
        algorithm=algorithm,
        common_ports_first=common_ports_first,
        max_threads=max_threads,
        scan_id=scan_id,
        port_range=port_range
    )
    threading.Thread(target=scanner.run, daemon=True).start()

    return jsonify({'scan_id': scan_id, 'status': 'started', 'target': target})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    result = scan_results[scan_id]
    result['status'] = scan_status.get(scan_id, 'unknown')
    return jsonify(result)

@app.route('/api/scan/<scan_id>/export/pdf', methods=['GET'])
def export_pdf(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = scan_results[scan_id]

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height-50, "PortMaster Scan Report")
    c.setFont("Helvetica", 10)
    c.drawString(50, height-80, f"Target: {scan_data['target']}")
    c.drawString(50, height-95, f"Algorithm: {scan_data['algorithm']}")
    c.drawString(50, height-110, f"Start: {scan_data['start_time']}")
    c.drawString(50, height-125, f"Total Ports: {scan_data['total_ports']}")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height-155, "Open Ports:")
    y = height-170

    if not scan_data['open_ports']:
        c.drawString(50, y, "No open ports found.")
    else:
        for port in scan_data['open_ports']:
            c.drawString(50, y, f"{port['port']} ({port['service']}) - Risk: {port['risk_level']}")
            y -= 15
            if y < 50:
                c.showPage()
                y = height-50

    c.showPage()
    c.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"scan-{scan_id}.pdf", mimetype='application/pdf')

# Route untuk ambil semua scan history
@app.route('/api/scans', methods=['GET'])
def list_all_scans():
    history = []
    for scan_id, data in scan_results.items():
        entry = {
            'scan_id': scan_id,
            'target': data['target'],
            'algorithm': data['algorithm'],
            'start_time': data['start_time'],
            'status': scan_status.get(scan_id, 'unknown'),
            'open_ports': data['open_ports']
        }
        history.append(entry)
    return jsonify(history)

# -----------------------------
# RUN SERVER
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
