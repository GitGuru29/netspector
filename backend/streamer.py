import json
import asyncio
import time
from collections import deque
import websockets

from intelligence.classifier import ThreatClassifier

class Streamer:
    def __init__(self, aggregator, host="127.0.0.1", port=8765):
        self.aggregator = aggregator
        self.host = host
        self.port = port
        self.clients = set()
        self.running = False
        self.classifier = ThreatClassifier()
        self.recent_events = deque()
        self.replay_window_seconds = 60

    async def register(self, websocket):
        self.clients.add(websocket)
        consumer_task = asyncio.create_task(self.handle_client_messages(websocket))
        try:
            await websocket.wait_closed()
        finally:
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            self.clients.discard(websocket)

    async def handle_client_messages(self, websocket):
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if msg.get("type") != "replay_request":
                continue

            try:
                requested_seconds = int(msg.get("seconds", self.replay_window_seconds))
            except (TypeError, ValueError):
                requested_seconds = self.replay_window_seconds
            window_seconds = max(5, min(300, requested_seconds))
            now = time.time()
            frames = [
                {"ts": event["ts"], "data": event["data"]}
                for event in self.recent_events
                if now - event["ts"] <= window_seconds
            ]
            await websocket.send(json.dumps({
                "type": "replay_data",
                "window_seconds": window_seconds,
                "data": frames
            }))

    async def emit_loop(self):
        while self.running:
            if self.clients:
                # Get current flows
                flows = self.aggregator.get_active_flows()
                
                # Classify flows
                classified_flows = self.classifier.analyze(flows)

                now = time.time()
                self.recent_events.append({"ts": now, "data": classified_flows})
                while self.recent_events and (now - self.recent_events[0]["ts"] > self.replay_window_seconds):
                    self.recent_events.popleft()
                
                message = json.dumps({"type": "flows", "data": classified_flows})

                # Broadcast and evict broken connections
                clients = list(self.clients)
                results = await asyncio.gather(
                    *[client.send(message) for client in clients],
                    return_exceptions=True
                )
                for client, result in zip(clients, results):
                    if isinstance(result, Exception):
                        self.clients.discard(client)
            
            # 100ms emission rate
            await asyncio.sleep(0.1)

    async def start_server(self):
        print(f"[*] Starting WebSocket Streamer on ws://{self.host}:{self.port}")
        self.running = True
        
        async with websockets.serve(self.register, self.host, self.port):
            await self.emit_loop()

    def run(self):
        asyncio.run(self.start_server())
