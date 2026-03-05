import argparse
from aggregator import FlowAggregator
from sniffer import PacketEngine
from streamer import Streamer

def main():
    parser = argparse.ArgumentParser(description="NetSpectre Backend Engine")
    parser.add_argument("--mode", choices=["live", "simulate"], default="live",
                        help="Mode: live capture (default) or simulate.")
    parser.add_argument("--iface", default=None,
                        help="Network interface for live capture (e.g., en0)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="WebSocket bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket Port")
    args = parser.parse_args()

    # 1. Initialize Aggregator
    aggregator = FlowAggregator(timeout=10) # 10 sec timeout for inactive flows

    # 2. Initialize and Start Sniffer
    engine = PacketEngine(mode=args.mode, aggregator=aggregator, iface=args.iface)
    engine.start()

    # 3. Initialize and Start WebSocket Streamer
    # This runs the asyncio loop on the main thread
    streamer = Streamer(aggregator=aggregator, host=args.host, port=args.port)
    
    try:
        streamer.run()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        engine.stop()

if __name__ == "__main__":
    main()
