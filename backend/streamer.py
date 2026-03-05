import json
import asyncio
import websockets

from intelligence.classifier import ThreatClassifier

class Streamer:
    def __init__(self, aggregator, host="0.0.0.0", port=8765):
        self.aggregator = aggregator
        self.host = host
        self.port = port
        self.clients = set()
        self.running = False
        self.classifier = ThreatClassifier()

    async def register(self, websocket):
        self.clients.add(websocket)
        try:
            await websocket.wait_closed()
        finally:
            self.clients.remove(websocket)

    async def emit_loop(self):
        while self.running:
            if self.clients:
                # Get current flows
                flows = self.aggregator.get_active_flows()
                
                # Classify flows
                classified_flows = self.classifier.analyze(flows)
                
                message = json.dumps({"type": "flows", "data": classified_flows})
                
                # Broadcast
                await asyncio.gather(
                    *[client.send(message) for client in self.clients],
                    return_exceptions=True
                )
            
            # 100ms emission rate
            await asyncio.sleep(0.1)

    async def start_server(self):
        print(f"[*] Starting WebSocket Streamer on ws://{self.host}:{self.port}")
        self.running = True
        
        async with websockets.serve(self.register, self.host, self.port):
            await self.emit_loop()

    def run(self):
        asyncio.run(self.start_server())
