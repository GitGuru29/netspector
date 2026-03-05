import time
import random
import threading
from scapy.all import sniff, IP, TCP, UDP
from aggregator import FlowAggregator

class PacketEngine:
    def __init__(self, mode="simulate", aggregator=None):
        self.mode = mode
        self.aggregator = aggregator or FlowAggregator()
        self.running = False
        
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

    def _process_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "OTHER"
            sport = 0
            dport = 0
            
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                
            length = len(packet)
            self.aggregator.add_packet(src, dst, sport, dport, proto, length)

    def _live_capture(self):
        print("[*] Starting live capture (requires sudo)...")
        # filter="ip" ensures we only get IP packets
        sniff(filter="ip", prn=self._process_packet, store=False, stop_filter=lambda p: not self.running)

    def _simulate_traffic(self):
        print("[*] Starting synthetic traffic simulation...")
        while self.running:
            # 80% normal traffic
            if random.random() < 0.8:
                src = random.choice(self.mock_nodes)
                dst = random.choice(self.mock_nodes)
                while dst == src:
                    dst = random.choice(self.mock_nodes)
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 53, 22])
                proto = random.choice(["TCP", "UDP"])
                size = random.randint(64, 1500)
                self.aggregator.add_packet(src, dst, sport, dport, proto, size)
            
            # 15% scan traffic (one attacker to many ports)
            elif random.random() < 0.95:
                src = random.choice(self.attackers)
                dst = random.choice(self.mock_nodes)
                sport = random.randint(1024, 65535)
                dport = random.randint(1, 1024)
                size = 60 # SYN packet
                self.aggregator.add_packet(src, dst, sport, dport, "TCP", size)
                
            # 5% data exfil (massive UDP stream)
            else:
                src = random.choice(self.mock_nodes)
                dst = random.choice(self.attackers)
                sport = random.randint(1024, 65535)
                dport = random.choice([53, 443])
                for _ in range(10): # Burst
                    self.aggregator.add_packet(src, dst, sport, dport, "UDP", 1500)
            
            time.sleep(random.uniform(0.01, 0.05)) # High frequency
