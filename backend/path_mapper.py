import re
import time
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor


class PathMapper:
    def __init__(self, max_hops=24, timeout=20, cache_ttl=300):
        self.max_hops = max_hops
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._inflight = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4)

    def _parse_traceroute(self, output):
        hops = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Hop lines usually start with an integer index.
            if not line[0].isdigit():
                continue
            match = ip_pattern.search(line)
            if match:
                hops.append(match.group(0))
        return hops

    def _trace_target(self, target):
        cmd = ["traceroute", "-n", "-m", str(self.max_hops), "-w", "1", target]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if result.returncode not in (0, 1):
            return []
        return self._parse_traceroute(result.stdout)

    def request_trace(self, target):
        now = time.time()
        with self._lock:
            cached = self._cache.get(target)
            if cached and now - cached["ts"] < self.cache_ttl:
                return
            if target in self._inflight:
                return
            future = self._pool.submit(self._trace_target, target)
            self._inflight[target] = future

    def refresh(self):
        completed = []
        with self._lock:
            for target, future in list(self._inflight.items()):
                if future.done():
                    completed.append((target, future))
                    del self._inflight[target]
        for target, future in completed:
            try:
                hops = future.result()
            except Exception:
                hops = []
            with self._lock:
                self._cache[target] = {"ts": time.time(), "hops": hops}

    def get_paths(self):
        now = time.time()
        with self._lock:
            # Keep only still-valid cache records.
            stale = [k for k, v in self._cache.items() if now - v["ts"] > self.cache_ttl]
            for key in stale:
                del self._cache[key]
            return {target: value["hops"] for target, value in self._cache.items()}
