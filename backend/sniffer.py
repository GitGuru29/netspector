import time
import random
import threading
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, DNS, conf
from aggregator import FlowAggregator

class PacketEngine:
    def __init__(self, mode="simulate", aggregator=None, iface=None):
        self.mode = mode
        self.aggregator = aggregator or FlowAggregator()
        self.iface = iface
        self.running = False
        self._sniffer = None
        self._packet_count = 0
        
        # Simulation parameters
        self.mock_nodes = [
            f"192.168.1.{i}" for i in range(10, 50)
        ] + ["8.8.8.8", "1.1.1.1", "104.21.43.5", "185.199.108.153"]
        self.attackers = ["45.33.32.156", "185.220.101.5", "91.132.145.22"]

    def start(self):
        self.running = True
        if self.mode == "simulate":
            threading.Thread(target=self._simulate_traffic, daemon=True).start()
        elif self.mode == "live":
            threading.Thread(target=self._live_capture, daemon=True).start()

    def stop(self):
        self.running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            finally:
                self._sniffer = None

    def _process_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "OTHER"
            sport = 0
            dport = 0
            flags = {"ttl": int(packet[IP].ttl)}
            
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                # SYN scan traffic: SYN set and ACK not set.
                flags["tcp_syn"] = bool((packet[TCP].flags & 0x02) and ((packet[TCP].flags & 0x10) == 0))
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
            elif ICMP in packet:
                proto = "ICMP"
                # ICMP flood heuristic focuses on echo requests.
                flags["icmp_echo"] = int(packet[ICMP].type) == 8

            if DNS in packet and int(packet[DNS].qr) == 0:
                flags["dns_query"] = True
                
            length = len(packet)
            self._packet_count += 1
            self.aggregator.add_packet(src, dst, sport, dport, proto, length, flags=flags)

    def _live_capture(self):
        capture_iface = self.iface or "default"
        print(f"[*] Starting live capture on interface: {capture_iface} (requires sudo)...")
        try:
            conf.use_pcap = True
            print("[*] libpcap capture enabled")
        except Exception:
            print("[!] libpcap unavailable, using native capture backend")
        print(f"[*] tcpdump parity check: sudo tcpdump -nn -i {capture_iface} ip")

        # Async sniffer lets us stop promptly even when traffic is idle.
        self._sniffer = AsyncSniffer(iface=self.iface, filter="ip", prn=self._process_packet, store=False)
        self._sniffer.start()
        try:
            last_count = self._packet_count
            last_warn_at = 0.0
            while self.running:
                now = time.time()
                if now - last_warn_at >= 8.0:
                    if self._packet_count == last_count:
                        print("[!] No packets captured yet. Check sudo privileges and interface selection.")
                    last_count = self._packet_count
                    last_warn_at = now
                time.sleep(0.2)
        finally:
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                finally:
                    self._sniffer = None

    def _simulate_traffic(self):
        print("[*] Starting synthetic traffic simulation...")
        while self.running:
            r = random.random()
            # 70% normal traffic
            if r < 0.70:
                src = random.choice(self.mock_nodes)
                dst = random.choice(self.mock_nodes)
                while dst == src:
                    dst = random.choice(self.mock_nodes)
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 53, 22])
                proto = random.choice(["TCP", "UDP"])
                size = random.randint(64, 1500)
                self.aggregator.add_packet(src, dst, sport, dport, proto, size)
            
            # 15% SYN scan traffic (one attacker to many ports)
            elif r < 0.85:
                src = random.choice(self.attackers)
                dst = random.choice(self.mock_nodes)
                sport = random.randint(1024, 65535)
                dport = random.randint(1, 1024)
                size = 60 # SYN packet
                self.aggregator.add_packet(src, dst, sport, dport, "TCP", size, flags={"tcp_syn": True})
                
            # 8% ICMP flood bursts
            elif r < 0.93:
                src = random.choice(self.attackers)
                dst = random.choice(self.mock_nodes)
                for _ in range(20):
                    self.aggregator.add_packet(src, dst, 0, 0, "ICMP", random.randint(64, 128), flags={"icmp_echo": True})

            # 7% DNS anomaly bursts
            else:
                src = random.choice(self.mock_nodes)
                dst = random.choice(["8.8.8.8", "1.1.1.1"])
                sport = random.randint(1024, 65535)
                dport = 53
                for _ in range(15):
                    self.aggregator.add_packet(src, dst, sport, dport, "UDP", random.randint(70, 180), flags={"dns_query": True})
            
            time.sleep(random.uniform(0.01, 0.05)) # High frequency
