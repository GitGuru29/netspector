import time
from collections import defaultdict

class ThreatClassifier:
    def __init__(self):
        # Tracking states for heuristics (per source IP)
        self.ip_ports = defaultdict(set)
        self.ip_port_time = defaultdict(float)
        self.ip_syn = defaultdict(int)
        self.ip_syn_time = defaultdict(float)
        self.ip_icmp = defaultdict(int)
        self.ip_icmp_time = defaultdict(float)
        self.ip_dns = defaultdict(int)
        self.ip_dns_time = defaultdict(float)
        self.last_flow_bytes = {}
        self.last_flow_syn = {}
        self.last_flow_icmp = {}
        self.last_flow_dns = {}
        self.ip_last_seen = defaultdict(float)

        # Thresholds
        self.CHECK_WINDOW = 3.0
        self.SYN_SCAN_SYN_THRESHOLD = 12
        self.SYN_SCAN_PORT_THRESHOLD = 10
        self.PORT_SWEEP_THRESHOLD = 18
        self.ICMP_FLOOD_THRESHOLD = 20
        self.DNS_ANOMALY_THRESHOLD = 15

    def analyze(self, flows):
        """Analyze a snapshot of active flow objects, returning a list of dicts with updated threat metrics."""
        current_time = time.time()
        active_flow_ids = set()
        
        # 1. Update heuristics from current flow snapshot
        for flow in flows:
            flow_id = flow["id"]
            src = flow["src"]
            dst_port = flow["dst_port"]
            total_volume = flow["bytes"]
            prev_volume = self.last_flow_bytes.get(flow_id, 0)
            volume_delta = total_volume - prev_volume if total_volume >= prev_volume else total_volume
            total_syn = flow.get("syn_packets", 0)
            prev_syn = self.last_flow_syn.get(flow_id, 0)
            syn_delta = total_syn - prev_syn if total_syn >= prev_syn else total_syn
            total_icmp = flow.get("icmp_packets", 0)
            prev_icmp = self.last_flow_icmp.get(flow_id, 0)
            icmp_delta = total_icmp - prev_icmp if total_icmp >= prev_icmp else total_icmp
            total_dns = flow.get("dns_queries", 0)
            prev_dns = self.last_flow_dns.get(flow_id, 0)
            dns_delta = total_dns - prev_dns if total_dns >= prev_dns else total_dns

            active_flow_ids.add(flow_id)
            self.last_flow_bytes[flow_id] = total_volume
            self.last_flow_syn[flow_id] = total_syn
            self.last_flow_icmp[flow_id] = total_icmp
            self.last_flow_dns[flow_id] = total_dns
            
            # Reset window if needed
            if current_time - self.ip_port_time[src] > self.CHECK_WINDOW:
                self.ip_ports[src] = set()
                self.ip_port_time[src] = current_time
                
            if current_time - self.ip_syn_time[src] > self.CHECK_WINDOW:
                self.ip_syn[src] = 0
                self.ip_syn_time[src] = current_time

            if current_time - self.ip_icmp_time[src] > self.CHECK_WINDOW:
                self.ip_icmp[src] = 0
                self.ip_icmp_time[src] = current_time

            if current_time - self.ip_dns_time[src] > self.CHECK_WINDOW:
                self.ip_dns[src] = 0
                self.ip_dns_time[src] = current_time
            
            # Record
            self.ip_ports[src].add(dst_port)
            self.ip_syn[src] += max(0, syn_delta)
            self.ip_icmp[src] += max(0, icmp_delta)
            self.ip_dns[src] += max(0, dns_delta)
            self.ip_last_seen[src] = current_time

        # Prune flow state for flows that timed out in the aggregator.
        stale_flow_ids = [flow_id for flow_id in self.last_flow_bytes if flow_id not in active_flow_ids]
        for flow_id in stale_flow_ids:
            del self.last_flow_bytes[flow_id]
            self.last_flow_syn.pop(flow_id, None)
            self.last_flow_icmp.pop(flow_id, None)
            self.last_flow_dns.pop(flow_id, None)

        # Prune source-IP state for inactive sources to prevent unbounded growth.
        stale_ips = [ip for ip, last_seen in self.ip_last_seen.items()
                     if current_time - last_seen > (self.CHECK_WINDOW * 4)]
        for ip in stale_ips:
            self.ip_ports.pop(ip, None)
            self.ip_port_time.pop(ip, None)
            self.ip_syn.pop(ip, None)
            self.ip_syn_time.pop(ip, None)
            self.ip_icmp.pop(ip, None)
            self.ip_icmp_time.pop(ip, None)
            self.ip_dns.pop(ip, None)
            self.ip_dns_time.pop(ip, None)
            self.ip_last_seen.pop(ip, None)

        # 2. Classify flows based on the source IP's behavior
        classified_flows = []
        for flow in flows:
            src = flow["src"]
            classification = "normal"
            risk_score = 0

            syn_rate = self.ip_syn[src]
            port_count = len(self.ip_ports[src])
            icmp_rate = self.ip_icmp[src]
            dns_rate = self.ip_dns[src]

            # SYN scan: many SYNs to many ports in short window.
            if syn_rate >= self.SYN_SCAN_SYN_THRESHOLD and port_count >= self.SYN_SCAN_PORT_THRESHOLD:
                classification = "syn_scan"
                risk_score = min(100, 55 + port_count)

            # Port sweep: many unique destination ports even with lower SYN count.
            if port_count >= self.PORT_SWEEP_THRESHOLD and risk_score < 70:
                classification = "port_sweep"
                risk_score = min(95, 40 + port_count)

            # ICMP flood: high echo-request rate.
            if icmp_rate >= self.ICMP_FLOOD_THRESHOLD and risk_score < 90:
                classification = "icmp_flood"
                risk_score = min(100, 60 + int(icmp_rate / 3))

            # DNS anomalies: unusually high query rate.
            if dns_rate >= self.DNS_ANOMALY_THRESHOLD and risk_score < 85:
                classification = "dns_anomaly"
                risk_score = min(95, 50 + dns_rate // 2)
            
            # Update flow dict
            flow["classification"] = classification
            flow["risk_score"] = risk_score
            classified_flows.append(flow)

        return classified_flows
