import threading
import argparse
from aggregator import FlowAggregator
from sniffer import PacketEngine
from streamer import Streamer

def main():
    parser = argparse.ArgumentParser(description="NetSpectre Backend Engine")
    parser.add_argument("--mode", choices=["live", "simulate"], default="simulate",
                        help="Mode: live capture (needs sudo) or simulate.")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket Port")
    args = parser.parse_args()

    # 1. Initialize Aggregator
    aggregator = FlowAggregator(timeout=10) # 10 sec timeout for inactive flows

    # 2. Initialize and Start Sniffer
    engine = PacketEngine(mode=args.mode, aggregator=aggregator)
    engine.start()

    # 3. Initialize and Start WebSocket Streamer
    # This runs the asyncio loop on the main thread
    streamer = Streamer(aggregator=aggregator, port=args.port)
    
    try:
        streamer.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        engine.stop()

if __name__ == "__main__":
    main()
