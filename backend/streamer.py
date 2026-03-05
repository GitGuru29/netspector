import json
import asyncio
import time
from collections import deque
import websockets

from intelligence.classifier import ThreatClassifier
from path_mapper import PathMapper

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
        self.path_mapper = PathMapper()

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
                for flow in classified_flows:
                    src = flow.get("src")
                    dst = flow.get("dst")
                    if self._is_private_ip(src) and not self._is_private_ip(dst):
                        self.path_mapper.request_trace(dst)
                    elif not self._is_private_ip(src) and self._is_private_ip(dst):
                        self.path_mapper.request_trace(src)
                self.path_mapper.refresh()
                paths = self.path_mapper.get_paths()

                now = time.time()
                self.recent_events.append({"ts": now, "data": classified_flows})
                while self.recent_events and (now - self.recent_events[0]["ts"] > self.replay_window_seconds):
                    self.recent_events.popleft()
                
                message = json.dumps({"type": "flows", "data": classified_flows, "paths": paths})

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
