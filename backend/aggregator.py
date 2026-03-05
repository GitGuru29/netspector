import time
import hashlib
from collections import defaultdict
import threading

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.packet_count = 0
        self.byte_volume = 0
        self.start_time = time.time()
        self.last_seen = time.time()
        
        # Risk classification (0 = normal, higher = worse)
        self.risk_score = 0
        self.classification = "normal"
        
        # Determine flow ID
        self.flow_id = self._generate_id()

    def _generate_id(self):
        s = f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
        return hashlib.md5(s.encode()).hexdigest()[:12]

    def update(self, packet_size):
        self.packet_count += 1
        self.byte_volume += packet_size
        self.last_seen = time.time()

    def to_dict(self):
        return {
            "id": self.flow_id,
            "src": self.src_ip,
            "dst": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packets": self.packet_count,
            "bytes": self.byte_volume,
            "duration": self.last_seen - self.start_time,
            "risk_score": self.risk_score,
            "classification": self.classification
        }

class FlowAggregator:
    def __init__(self, timeout=30):
        # Maps flow_id -> Flow object
        self.flows = {}
        self.timeout = timeout
        self.lock = threading.Lock()
        
    def add_packet(self, src_ip, dst_ip, src_port, dst_port, protocol, size):
        # We use a simple directional flow ID
        s = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        flow_id = hashlib.md5(s.encode()).hexdigest()[:12]
        
        with self.lock:
            if flow_id not in self.flows:
                self.flows[flow_id] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
                
            self.flows[flow_id].update(size)
        
    def get_active_flows(self):
        # Clean up old flows and return active ones
        current_time = time.time()
        active = []
        to_delete = []
        
        with self.lock:
            for f_id, flow in list(self.flows.items()):
                if current_time - flow.last_seen > self.timeout:
                    to_delete.append(f_id)
                else:
                    active.append(flow.to_dict())
                    
            for f_id in to_delete:
                if f_id in self.flows:
                    del self.flows[f_id]
                
        return active
