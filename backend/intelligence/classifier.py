import time
from collections import defaultdict

class ThreatClassifier:
    def __init__(self):
        # Tracking states for heuristics
        self.ip_ports = defaultdict(set)
        self.ip_port_time = defaultdict(time.time)
        self.ip_bytes = defaultdict(int)
        self.ip_bytes_time = defaultdict(time.time)

        # Thresholds
        self.SCANNER_PORT_THRESHOLD = 15 # connected to 15 different ports in a tiny window
        self.DOS_BYTE_THRESHOLD = 500000 # half a megabyte in a tiny window
        self.CHECK_WINDOW = 2.0 # 2 seconds

    def analyze(self, flows):
        """Analyze a snapshot of active flow objects, returning a list of dicts with updated threat metrics."""
        current_time = time.time()
        
        # 1. Update heuristics from current flow snapshot
        for flow in flows:
            src = flow["src"]
            dst_port = flow["dst_port"]
            volume = flow["bytes"]
            
            # Reset window if needed
            if current_time - self.ip_port_time[src] > self.CHECK_WINDOW:
                self.ip_ports[src] = set()
                self.ip_port_time[src] = current_time
                
            if current_time - self.ip_bytes_time[src] > self.CHECK_WINDOW:
                self.ip_bytes[src] = 0
                self.ip_bytes_time[src] = current_time
            
            # Record
            self.ip_ports[src].add(dst_port)
            self.ip_bytes[src] += volume

        # 2. Classify flows based on the source IP's behavior
        classified_flows = []
        for flow in flows:
            src = flow["src"]
            dst = flow["dst"]
            dst_port = flow["dst_port"]

            classification = "normal"
            risk_score = 0

            # Rule 1: Port Scanner Detection
            port_count = len(self.ip_ports[src])
            if port_count >= self.SCANNER_PORT_THRESHOLD:
                classification = "scanner"
                risk_score = min(100, port_count * 5)
                
            # Rule 2: DoS or Exfiltration Detection
            byte_vol = self.ip_bytes[src]
            if byte_vol > self.DOS_BYTE_THRESHOLD:
                if classification == "scanner":
                    # Elevate existing
                     classification = "dos+scanner"
                else:
                    classification = "dos" if str(src).startswith("185.") or str(src).startswith("45.") or str(src).startswith("91.") else "exfiltration"
                risk_score = min(100, int((byte_vol / self.DOS_BYTE_THRESHOLD) * 50))
            
            # C2 Beacon (Rhythmic pinging mock)
            if flow["packets"] > 0 and (flow["duration"] > 10) and (flow["bytes"] / flow["packets"] < 100) and dst_port in [53, 443]:
                 if classification == "normal":
                     classification = "c2_beacon"
                     risk_score = 80
            
            # Update flow dict
            flow["classification"] = classification
            flow["risk_score"] = risk_score
            classified_flows.append(flow)

        return classified_flows
