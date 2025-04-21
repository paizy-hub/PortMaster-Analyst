import socket
import threading
import time
from datetime import datetime
from collections import deque
from flask import Flask, request, jsonify, render_template
import json

app = Flask(__name__, static_folder='static')


# Global variables to track scan progress
scan_results = {}
scan_status = {}

class PortScanner:
    def __init__(self, target, algorithm='bfs', common_ports_first=True, max_threads=100, scan_id=None):
        self.target = target
        self.algorithm = algorithm.lower()
        self.common_ports_first = common_ports_first
        self.max_threads = max_threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.active_threads = 0
        self.thread_semaphore = threading.Semaphore(max_threads)
        self.scan_id = scan_id
        
        # Daftar port yang umum digunakan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]
    
    def scan_port(self, port):
        """Scan satu port dan tambahkan ke daftar jika terbuka"""
        try:
            with self.thread_semaphore:
                with self.lock:
                    self.active_threads += 1
                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                
                if result == 0:
                    service = self.get_service_name(port)
                    with self.lock:
                        self.open_ports.append((port, service))
                        # Update scan results in global dict
                        if self.scan_id:
                            scan_results[self.scan_id]['open_ports'].append({'port': port, 'service': service})
                            scan_results[self.scan_id]['progress'] += 1
                s.close()
                
                with self.lock:
                    self.active_threads -= 1
        except:
            with self.lock:
                self.active_threads -= 1
        
        # Update progress
        if self.scan_id:
            scan_results[self.scan_id]['progress'] += 1
    
    def get_service_name(self, port):
        """Identifikasi nama service berdasarkan port"""
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
    
    def bfs_scan(self):
        """Algoritma BFS untuk port scanning"""
        # Inisialisasi queue untuk BFS
        queue = deque()
        visited = set()
        
        # Tambahkan port umum dulu jika diaktifkan
        if self.common_ports_first:
            for port in self.common_ports:
                queue.append(port)
                visited.add(port)
        
        # Tambahkan range port lainnya
        scan_range = range(1, 1025)  # Scan only first 1024 ports for web interface
        for port in scan_range:
            if port not in visited:
                queue.append(port)
                visited.add(port)
        
        total_ports = len(queue)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = total_ports
            scan_results[self.scan_id]['ports_to_scan'] = list(queue)
        
        # Mulai BFS scanning
        threads = []
        while queue:
            port = queue.popleft()  # Dequeue port dari depan (FIFO)
            
            # Tunggu jika thread sudah maksimal
            while self.active_threads >= self.max_threads:
                time.sleep(0.1)
            
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Tunggu semua thread selesai
        for t in threads:
            t.join()
        
        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed_time = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed_time:.2f}"
    
    def dfs_scan(self):
        """Algoritma DFS untuk port scanning"""
        # Inisialisasi stack untuk DFS
        stack = []
        visited = set()
        
        # Tambahkan port umum dulu jika diaktifkan
        if self.common_ports_first:
            for port in reversed(self.common_ports):  # Reversed agar port umum di-scan terlebih dahulu
                stack.append(port)
                visited.add(port)
        
        # Tambahkan range port lainnya
        scan_range = range(1024, 0, -1)  # Scan only first 1024 ports for web interface
        for port in scan_range:  # Reversed untuk DFS
            if port not in visited:
                stack.append(port)
                visited.add(port)
        
        total_ports = len(stack)
        if self.scan_id:
            scan_results[self.scan_id]['total_ports'] = total_ports
            scan_results[self.scan_id]['ports_to_scan'] = list(stack)
        
        # Mulai DFS scanning
        threads = []
        while stack:
            port = stack.pop()  # Pop port dari belakang (LIFO)
            
            # Tunggu jika thread sudah maksimal
            while self.active_threads >= self.max_threads:
                time.sleep(0.1)
            
            t = threading.Thread(target=self.scan_port, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Tunggu semua thread selesai
        for t in threads:
            t.join()
        
        if self.scan_id:
            scan_status[self.scan_id] = "completed"
            scan_results[self.scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            elapsed_time = time.time() - scan_results[self.scan_id]['start_timestamp']
            scan_results[self.scan_id]['elapsed_time'] = f"{elapsed_time:.2f}"
    
    def run(self):
        """Jalankan port scanner dengan algoritma yang dipilih"""
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
        elif self.algorithm == 'dfs':
            self.dfs_scan()
        else:
            self.bfs_scan()

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

# API endpoint to start a new scan
@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    algorithm = data.get('algorithm', 'bfs')
    common_ports_first = data.get('common_ports_first', True)
    max_threads = int(data.get('max_threads', 100))
    
    scan_id = f"{target}_{int(time.time())}"
    
    # Start scan in a background thread
    scanner = PortScanner(
        target=target,
        algorithm=algorithm,
        common_ports_first=common_ports_first,
        max_threads=max_threads,
        scan_id=scan_id
    )
    
    scan_thread = threading.Thread(target=scanner.run)
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'target': target
    })

# API endpoint to get scan status and results
@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    result = scan_results[scan_id].copy()
    result['status'] = scan_status.get(scan_id, 'unknown')
    
    return jsonify(result)

# API endpoint to get all scans
@app.route('/api/scans', methods=['GET'])
def get_all_scans():
    result = []
    for scan_id in scan_results:
        scan_data = scan_results[scan_id].copy()
        scan_data['scan_id'] = scan_id
        scan_data['status'] = scan_status.get(scan_id, 'unknown')
        result.append(scan_data)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)