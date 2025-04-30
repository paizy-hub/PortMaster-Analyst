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
from scapy.all import IP, TCP, UDP, ICMP, sr1

app = Flask(__name__, static_folder='static')

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

scan_results = {}
scan_status = {}

class PortScanner:
    def __init__(self, target, algorithm='bfs', common_ports_first=True, max_threads=100, scan_id=None, port_range=None, scan_method='connect'):
        self.target = target
        self.algorithm = algorithm.lower()
        self.common_ports_first = common_ports_first
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.thread_semaphore = threading.Semaphore(max_threads)
        self.scan_id = scan_id
        self.port_range = port_range if port_range else (1, 1024)
        self.common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
        self.scan_method = scan_method.lower()

        if port_range:
            self.common_ports = [p for p in self.common_ports if port_range[0] <= p <= port_range[1]]

    def add_open_port(self, port):
        service = self.get_service_name(port)
        with self.lock:
            self.open_ports.append((port, service))
            if self.scan_id:
                info = PORT_RISK_INFO.get(port, {"name": "Unknown", "risk_level": "Unknown", "description": "N/A", "recommendations": "N/A"})
                scan_results[self.scan_id]['open_ports'].append({
                    'port': port,
                    'service': service,
                    'risk_level': info['risk_level'],
                    'risk_description': info['description'],
                    'recommendations': info['recommendations']
                })

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

    def scan_port(self, port):
        try:
            if self.scan_method == 'connect': self.tcp_connect_scan(port)
            elif self.scan_method == 'syn': self.syn_scan(port)
            elif self.scan_method == 'ack': self.ack_scan(port)
            elif self.scan_method == 'fin': self.fin_scan(port)
            elif self.scan_method == 'null': self.null_scan(port)
            elif self.scan_method == 'xmas': self.xmas_scan(port)
            elif self.scan_method == 'udp': self.udp_scan(port)
        except: pass
        if self.scan_id:
            scan_results[self.scan_id]['progress'] += 1

    def tcp_connect_scan(self, port):
        with self.thread_semaphore:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0: self.add_open_port(port)
            s.close()

    def syn_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/TCP(dport=port, flags='S')
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
                self.add_open_port(port)

    def ack_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/TCP(dport=port, flags='A')
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x4:
                self.add_open_port(port)

    def fin_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/TCP(dport=port, flags='F')
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                self.add_open_port(port)

    def null_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/TCP(dport=port, flags=0)
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                self.add_open_port(port)

    def xmas_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/TCP(dport=port, flags='FPU')
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp is None:
                self.add_open_port(port)

    def udp_scan(self, port):
        with self.thread_semaphore:
            pkt = IP(dst=self.target)/UDP(dport=port)
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp is None:
                self.add_open_port(port)
            elif resp.haslayer(ICMP):
                if resp[ICMP].type != 3:
                    self.add_open_port(port)

    def bfs_scan(self):
        queue = deque(self.common_ports if self.common_ports_first else [])
        visited = set(queue)
        for port in range(self.port_range[0], self.port_range[1]+1):
            if port not in visited:
                queue.append(port)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = len(queue)
        threads = [threading.Thread(target=self.scan_port, args=(p,)) for p in queue]
        for t in threads: t.start()
        for t in threads: t.join()
        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed:.2f}"

    def dfs_scan(self):
        stack = list(reversed(self.common_ports) if self.common_ports_first else [])
        for port in range(self.port_range[1], self.port_range[0]-1, -1):
            if port not in stack:
                stack.append(port)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = len(stack)
        threads = [threading.Thread(target=self.scan_port, args=(p,)) for p in stack]
        for t in threads: t.start()
        for t in threads: t.join()
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    scanner = PortScanner(
        target=data['target'],
        algorithm=data.get('algorithm', 'bfs'),
        common_ports_first=data.get('common_ports_first', True),
        max_threads=int(data.get('max_threads', 100)),
        port_range=(int(data.get('port_range_start', 1)), int(data.get('port_range_end', 1024))),
        scan_id=f"{data['target']}_{int(time.time())}",
        scan_method=data.get('scan_method', 'connect')
    )
    threading.Thread(target=scanner.run, daemon=True).start()
    return jsonify({'scan_id': scanner.scan_id, 'status': 'started', 'target': scanner.target})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    result = scan_results[scan_id]
    result['status'] = scan_status.get(scan_id, 'unknown')
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
