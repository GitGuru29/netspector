import time
from collections import defaultdict
from math import sqrt

class ThreatClassifier:
    def __init__(self):
        # Tracking states for heuristics (per source IP)
        self.ip_ports = defaultdict(set)
        self.ip_port_time = defaultdict(float)
        self.ip_bytes = defaultdict(int)
        self.ip_bytes_time = defaultdict(float)
        self.ip_syn = defaultdict(int)
        self.ip_syn_time = defaultdict(float)
        self.ip_syn_ports = defaultdict(set)
        self.ip_syn_ports_time = defaultdict(float)
        self.ip_icmp = defaultdict(int)
        self.ip_icmp_time = defaultdict(float)
        self.ip_dns = defaultdict(int)
        self.ip_dns_time = defaultdict(float)
        self.ip_unusual_ports = defaultdict(int)
        self.ip_unusual_ports_time = defaultdict(float)
        self.last_flow_bytes = {}
        self.last_flow_syn = {}
        self.last_flow_icmp = {}
        self.last_flow_dns = {}
        self.ip_last_seen = defaultdict(float)
        self.byte_stats = defaultdict(lambda: {"n": 0, "mean": 0.0, "m2": 0.0})
        self.src_connection_total = defaultdict(int)
        self.edge_seen = defaultdict(int)

        # Thresholds
        self.CHECK_WINDOW = 3.0
        self.SYN_SCAN_SYN_THRESHOLD = 12
        self.SYN_SCAN_PORT_THRESHOLD = 10
        self.PORT_SWEEP_THRESHOLD = 18
        self.ICMP_FLOOD_THRESHOLD = 20
        self.DNS_ANOMALY_THRESHOLD = 15
        self.ZSCORE_THRESHOLD = 3.2
        self.ZSCORE_MIN_BASELINE = 10
        self.TRAFFIC_SPIKE_MIN_BYTES = 50000
        self.UNUSUAL_PORT_THRESHOLD = 6
        self.UNEXPECTED_PATTERN_MIN_HISTORY = 20
        self.REMOTE_HOP_THRESHOLD = 20

    def _is_private_ip(self, ip):
        parts = str(ip).split(".")
        if len(parts) != 4:
            return False
        try:
            p = [int(x) for x in parts]
        except ValueError:
            return False
        if p[0] == 10:
            return True
        if p[0] == 192 and p[1] == 168:
            return True
        if p[0] == 172 and 16 <= p[1] <= 31:
            return True
        if p[0] == 127:
            return True
        if p[0] == 169 and p[1] == 254:
            return True
        return False

    def _update_running_stats(self, src, value):
        stats = self.byte_stats[src]
        stats["n"] += 1
        delta = value - stats["mean"]
        stats["mean"] += delta / stats["n"]
        delta2 = value - stats["mean"]
        stats["m2"] += delta * delta2

    def _z_score(self, src, value):
        stats = self.byte_stats[src]
        if stats["n"] < self.ZSCORE_MIN_BASELINE:
            return 0.0
        variance = stats["m2"] / max(1, stats["n"] - 1)
        std_dev = sqrt(variance) if variance > 0 else 0.0
        if std_dev == 0:
            return 0.0
        return (value - stats["mean"]) / std_dev

    def _estimate_hops(self, observed_ttl):
        ttl = int(observed_ttl) if observed_ttl else 0
        if ttl <= 0:
            return 0
        # Approximate initial TTL baselines used by common stacks.
        candidates = [32, 60, 64, 128, 255]
        viable = [initial - ttl for initial in candidates if initial - ttl >= 0]
        return min(viable) if viable else 0

    def analyze(self, flows):
        """Analyze a snapshot of active flow objects, returning a list of dicts with updated threat metrics."""
        current_time = time.time()
        active_flow_ids = set()
        unexpected_pattern_flows = set()
        
        # 1. Update heuristics from current flow snapshot
        for flow in flows:
            flow_id = flow["id"]
            src = flow["src"]
            dst = flow["dst"]
            protocol = flow["protocol"]
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
            
            if current_time - self.ip_bytes_time[src] > self.CHECK_WINDOW:
                self.ip_bytes[src] = 0
                self.ip_bytes_time[src] = current_time
                
            if current_time - self.ip_syn_time[src] > self.CHECK_WINDOW:
                self.ip_syn[src] = 0
                self.ip_syn_time[src] = current_time
            if current_time - self.ip_syn_ports_time[src] > self.CHECK_WINDOW:
                self.ip_syn_ports[src] = set()
                self.ip_syn_ports_time[src] = current_time

            if current_time - self.ip_icmp_time[src] > self.CHECK_WINDOW:
                self.ip_icmp[src] = 0
                self.ip_icmp_time[src] = current_time

            if current_time - self.ip_dns_time[src] > self.CHECK_WINDOW:
                self.ip_dns[src] = 0
                self.ip_dns_time[src] = current_time

            if current_time - self.ip_unusual_ports_time[src] > self.CHECK_WINDOW:
                self.ip_unusual_ports[src] = 0
                self.ip_unusual_ports_time[src] = current_time
            
            # Record
            self.ip_ports[src].add(dst_port)
            self.ip_bytes[src] += max(0, volume_delta)
            self.ip_syn[src] += max(0, syn_delta)
            if syn_delta > 0:
                self.ip_syn_ports[src].add(dst_port)
            self.ip_icmp[src] += max(0, icmp_delta)
            self.ip_dns[src] += max(0, dns_delta)
            self.ip_last_seen[src] = current_time
            # Unexpected connection pattern: new edge after a source has baseline history.
            edge_key = (src, dst, protocol)
            if self.edge_seen[edge_key] == 0 and self.src_connection_total[src] >= self.UNEXPECTED_PATTERN_MIN_HISTORY:
                unexpected_pattern_flows.add(flow_id)
            self.edge_seen[edge_key] += 1
            self.src_connection_total[src] += 1

            # Unusual port behavior focuses on internal hosts scanning odd/system ports.
            common_ports = {53, 80, 123, 443, 22, 25}
            is_unusual_port = (
                self._is_private_ip(src) and
                (dst_port in {23, 3389, 5900, 2323, 4444, 5555, 6667} or
                 (dst_port < 1024 and dst_port not in common_ports))
            )
            if is_unusual_port:
                self.ip_unusual_ports[src] += 1

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
            self.ip_bytes.pop(ip, None)
            self.ip_bytes_time.pop(ip, None)
            self.ip_syn.pop(ip, None)
            self.ip_syn_time.pop(ip, None)
            self.ip_syn_ports.pop(ip, None)
            self.ip_syn_ports_time.pop(ip, None)
            self.ip_icmp.pop(ip, None)
            self.ip_icmp_time.pop(ip, None)
            self.ip_dns.pop(ip, None)
            self.ip_dns_time.pop(ip, None)
            self.ip_unusual_ports.pop(ip, None)
            self.ip_unusual_ports_time.pop(ip, None)
            self.ip_last_seen.pop(ip, None)

        # 2. Classify flows based on the source IP's behavior
        classified_flows = []
        spike_zscore_by_src = {
            src: self._z_score(src, self.ip_bytes[src]) for src in self.ip_bytes
        }
        for flow in flows:
            flow_id = flow["id"]
            src = flow["src"]
            classification = "normal"
            risk_score = 0

            byte_rate = self.ip_bytes[src]
            syn_rate = self.ip_syn[src]
            # Scan heuristics should only use TCP SYN destination ports.
            port_count = len(self.ip_syn_ports[src])
            icmp_rate = self.ip_icmp[src]
            dns_rate = self.ip_dns[src]
            z_score = spike_zscore_by_src.get(src, 0.0)
            hops_estimate = self._estimate_hops(flow.get("avg_ttl", 0))

            # SYN scan: many SYNs to many ports in short window.
            if syn_rate >= self.SYN_SCAN_SYN_THRESHOLD and port_count >= self.SYN_SCAN_PORT_THRESHOLD:
                classification = "syn_scan"
                risk_score = min(100, 55 + port_count)

            # Port sweep: many unique destination ports even with lower SYN count.
            if port_count >= self.PORT_SWEEP_THRESHOLD and syn_rate >= 4 and risk_score < 70:
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

            # Intelligence layer: Z-score traffic spikes.
            if z_score >= self.ZSCORE_THRESHOLD and byte_rate >= self.TRAFFIC_SPIKE_MIN_BYTES and risk_score < 80:
                classification = "traffic_spike"
                risk_score = min(90, 45 + int(z_score * 10))

            # Intelligence layer: unusual port activity.
            if self.ip_unusual_ports[src] >= self.UNUSUAL_PORT_THRESHOLD and risk_score < 75:
                classification = "unusual_port_activity"
                risk_score = min(85, 40 + (self.ip_unusual_ports[src] * 4))

            # Intelligence layer: unexpected connection pattern.
            if flow_id in unexpected_pattern_flows and risk_score < 70:
                classification = "unexpected_pattern"
                risk_score = 70

            # Remote-origin attacks: far path (~20+ routers) boosts severity.
            if classification != "normal" and hops_estimate >= self.REMOTE_HOP_THRESHOLD:
                classification = f"remote_{classification}"
                risk_score = min(100, risk_score + 10)
            
            # Update flow dict
            flow["classification"] = classification
            flow["risk_score"] = risk_score
            flow["hops_estimate"] = hops_estimate
            classified_flows.append(flow)

        # Update running baseline after classifying the current snapshot.
        for src, value in self.ip_bytes.items():
            self._update_running_stats(src, value)

        return classified_flows
