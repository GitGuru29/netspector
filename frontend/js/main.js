// NetSpectre Main Application Logic

function getNodeColor(node) {
    // Priority coloring: attacker > suspicious > user router > external > internal.
    if (node.isAttacker) return '#ff3333';
    if (node.isAnomaly) return '#ffaa00';
    if (node.isUserRouter) return '#00e5ff';
    if (node.role === 'router_hop') return '#6aa3ff';
    if (node.isExternal) return '#8b5cf6';
    return '#2f80ff';
}

function createRouterGlyph(node) {
    if (typeof THREE === 'undefined') return null;
    const color = getNodeColor(node);

    const makeRouterIcon = ({ accent = '#9cc8ff', size = 120, user = false } = {}) => {
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;

        // Transparent background + soft glow.
        ctx.clearRect(0, 0, size, size);
        ctx.shadowBlur = 10;
        ctx.shadowColor = accent;

        // Router body.
        ctx.fillStyle = '#13253f';
        ctx.strokeStyle = accent;
        ctx.lineWidth = 4;
        const bodyX = size * 0.2;
        const bodyY = size * 0.48;
        const bodyW = size * 0.6;
        const bodyH = size * 0.22;
        ctx.beginPath();
        if (typeof ctx.roundRect === 'function') {
            ctx.roundRect(bodyX, bodyY, bodyW, bodyH, 10);
            ctx.fill();
            ctx.stroke();
        } else {
            ctx.fillRect(bodyX, bodyY, bodyW, bodyH);
            ctx.strokeRect(bodyX, bodyY, bodyW, bodyH);
        }

        // Antennas.
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.moveTo(size * 0.3, bodyY);
        ctx.lineTo(size * 0.22, size * 0.24);
        ctx.moveTo(size * 0.7, bodyY);
        ctx.lineTo(size * 0.78, size * 0.24);
        ctx.stroke();

        // Wifi arcs.
        ctx.lineWidth = 3;
        [0.11, 0.17, 0.23].forEach((r) => {
            ctx.beginPath();
            ctx.arc(size * 0.5, size * 0.3, size * r, Math.PI * 1.05, Math.PI * 1.95);
            ctx.stroke();
        });

        // LEDs.
        ctx.fillStyle = '#67f4a8';
        [0.39, 0.5, 0.61].forEach((x) => {
            ctx.beginPath();
            ctx.arc(size * x, size * 0.59, 3.5, 0, Math.PI * 2);
            ctx.fill();
        });

        // User-router badge.
        if (user) {
            ctx.shadowBlur = 0;
            ctx.fillStyle = '#00e5ff';
            ctx.strokeStyle = '#dffbff';
            ctx.lineWidth = 3;
            ctx.beginPath();
            ctx.arc(size * 0.84, size * 0.2, size * 0.11, 0, Math.PI * 2);
            ctx.fill();
            ctx.stroke();
            ctx.fillStyle = '#022638';
            ctx.font = `bold ${Math.floor(size * 0.14)}px sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('U', size * 0.84, size * 0.2);
        }

        const texture = new THREE.CanvasTexture(canvas);
        texture.needsUpdate = true;
        const material = new THREE.SpriteMaterial({
            map: texture,
            transparent: true,
            depthWrite: false
        });
        const sprite = new THREE.Sprite(material);
        sprite.scale.set(16, 16, 1);
        return sprite;
    };

    if (node.isUserRouter) return makeRouterIcon({ accent: '#6ef7ff', user: true });
    if (node.role === 'router') return makeRouterIcon({ accent: color });

    if (node.role === 'router_hop') {
        return new THREE.Mesh(
            new THREE.TetrahedronGeometry(3.4, 0),
            new THREE.MeshBasicMaterial({ color })
        );
    }

    return null;
}

function isLikelyUserRouter(ip) {
    if (!isPrivateIp(ip)) return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return Number(parts[3]) === 1;
}

// 1. Initialize 3D Force Graph
const elem = document.getElementById('3d-graph');
const Graph = ForceGraph3D()(elem)
    .backgroundColor('#050505')
    .nodeRelSize(4)
    .nodeAutoColorBy('group')
    .nodeResolution(16)
    .nodeLabel(node => {
        const role = (node.role || 'internal_host').replace('_', ' ');
        const tag = node.isUserRouter ? '\nYOUR ROUTER' : '';
        return `${node.id}\n${role}${tag}`;
    })
    .nodeVal(node => {
        if (node.role === 'router_hop') return 3.5;
        if (node.isUserRouter) return 10;
        if (node.role === 'router') return 8;
        if (node.role === 'server') return 6;
        if (node.role === 'iot') return 4.5;
        return 4;
    })
    .linkDirectionalParticles(link => {
        if (link.attackType === 'scan') return 6;
        if (link.attackType === 'flood') return 12;
        if (link.attackType === 'exfil') return 9;
        return 2;
    })
    .linkDirectionalParticleWidth(1.2)
    .linkDirectionalParticleSpeed(link => {
        if (link.attackType === 'scan') return 0.028;
        if (link.attackType === 'flood') return 0.036;
        if (link.attackType === 'exfil') return 0.018;
        return link.particleSpeed;
    })
    .linkColor(link => {
        const t = Date.now();
        if (link.attackType === 'scan') {
            return Math.floor(t / 130) % 2 === 0 ? '#ffd24a' : '#ff9f1a';
        }
        if (link.attackType === 'flood') {
            return Math.floor(t / 170) % 2 === 0 ? '#ff2d2d' : '#ff6b6b';
        }
        if (link.attackType === 'exfil') {
            return Math.floor(t / 220) % 2 === 0 ? '#27f58f' : '#8dffcc';
        }
        return link.color;
    })
    .linkOpacity(link => {
        const phase = (Math.sin(Date.now() / 170) + 1) / 2;
        if (link.attackType === 'scan') return 0.45 + (phase * 0.25);
        if (link.attackType === 'flood') return 0.65 + (phase * 0.3);
        if (link.attackType === 'exfil') return 0.5 + (phase * 0.25);
        return link.opacity;
    })
    .linkWidth(link => {
        const phase = (Math.sin(Date.now() / 120) + 1) / 2;
        if (link.attackType === 'scan') return 1 + (phase * 1.2);
        if (link.attackType === 'flood') return 3.2 + (phase * 2.8);
        if (link.attackType === 'exfil') return 2 + (phase * 1.8);
        return link.width;
    })
    .enableNodeDrag(false)
    .nodeColor(node => getNodeColor(node))
    .nodeThreeObject(node => createRouterGlyph(node))
    .nodeThreeObjectExtend(true)
    .onNodeClick(node => {
        // Aim camera
        const distance = 100;
        const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
        Graph.cameraPosition(
            { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
            node,
            3000
        );
    });

// Keep node positions stable in fixed visualization zones.
Graph.cooldownTicks(0);
setInterval(() => {
    if (typeof Graph.refresh === 'function') Graph.refresh();
}, 120);

// State mapping
let graphData = { nodes: [], links: [] };
let nodeSet = new Set();
let threatCount = 0;
const nodeLastSeen = new Map();
const threatLogCooldown = new Map();
const NODE_TTL_MS = 30000;
const MAX_NODES = 300;
const THREAT_LOG_COOLDOWN_MS = 5000;
const FEED_STATUS_INTERVAL_MS = 8000;
let lastFeedStatusAt = 0;
const nodeContext = new Map();
const hostStats = new Map();
const ANOMALY_SCORE_THRESHOLD = 60;

function isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    return false;
}

function isExternalIp(ip) {
    return !isPrivateIp(ip);
}

function getContext(ip) {
    if (!nodeContext.has(ip)) {
        nodeContext.set(ip, {
            peers: new Set(),
            dstPorts: new Set(),
            srcPorts: new Set(),
            inbound: 0,
            outbound: 0,
            lastSeen: Date.now()
        });
    }
    return nodeContext.get(ip);
}

function getHostStats(ip) {
    if (!hostStats.has(ip)) {
        hostStats.set(ip, {
            cps: { n: 0, mean: 0, m2: 0 },
            pps: { n: 0, mean: 0, m2: 0 },
            ports: { n: 0, mean: 0, m2: 0 }
        });
    }
    return hostStats.get(ip);
}

function updateRollingStat(stat, value) {
    stat.n += 1;
    const delta = value - stat.mean;
    stat.mean += delta / stat.n;
    const delta2 = value - stat.mean;
    stat.m2 += delta * delta2;
}

function zScore(stat, value) {
    if (stat.n < 10) return 0;
    const variance = stat.m2 / Math.max(1, stat.n - 1);
    const std = Math.sqrt(Math.max(variance, 0));
    if (!std) return 0;
    return (value - stat.mean) / std;
}


function deriveRole(ip) {
    if (isExternalIp(ip)) return 'external_ip';
    const ctx = nodeContext.get(ip);
    if (!ctx) return 'internal_host';

    const lastOctet = Number(ip.split('.')[3]);
    const servicePorts = [22, 53, 80, 443, 3306, 5432, 8080, 8443];
    const iotPorts = [1883, 5683, 554, 8883, 123];
    const hasServicePort = servicePorts.some(p => ctx.dstPorts.has(p) || ctx.srcPorts.has(p));
    const hasIotPort = iotPorts.some(p => ctx.dstPorts.has(p) || ctx.srcPorts.has(p));

    if (lastOctet === 1 || ctx.peers.size >= 25) return 'router';
    if (hasServicePort || (ctx.inbound > 20 && ctx.inbound > ctx.outbound * 1.2)) return 'server';
    if (hasIotPort || (ctx.peers.size <= 6 && ctx.outbound > 8 && ctx.inbound <= ctx.outbound)) return 'iot';
    return 'internal_host';
}

function hashString(input) {
    let h = 2166136261;
    for (let i = 0; i < input.length; i++) {
        h ^= input.charCodeAt(i);
        h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
    }
    return h >>> 0;
}

function fixedNodePosition(node) {
    const seed = hashString(node.id);
    const angleA = (seed % 360) * (Math.PI / 180);
    const angleB = ((seed >>> 9) % 360) * (Math.PI / 180);
    const jitter = (seed % 17) - 8;

    let radius = 95;
    if (node.isExternal) radius = 210;
    if (node.role === 'router') radius = 35;
    if (node.role === 'server') radius = 70;
    if (node.role === 'iot') radius = 120;
    if (node.role === 'router_hop') radius = 155;

    return {
        x: Math.cos(angleA) * radius + (jitter * 0.9),
        y: Math.sin(angleB) * (radius * 0.5) + (jitter * 0.6),
        z: Math.sin(angleA) * radius + (jitter * 0.9)
    };
}

// Update HUD
const statFlows = document.getElementById('stat-flows');
const statThreats = document.getElementById('stat-threats');
const statStatus = document.getElementById('stat-status');
const threatLogs = document.getElementById('threat-logs');
const replayBtn = document.getElementById('replay-btn');
let replayTimer = null;
let replayMode = false;
let userRouterIp = null;

function logThreat(msg, isCritical = false) {
    const li = document.createElement('li');
    li.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    if (isCritical) li.className = 'critical';
    threatLogs.prepend(li);
    if (threatLogs.children.length > 15) {
        threatLogs.removeChild(threatLogs.lastChild);
    }
}

function logThreatWithCooldown(key, msg, isCritical = false) {
    const now = Date.now();
    const lastLogged = threatLogCooldown.get(key) || 0;
    if (now - lastLogged < THREAT_LOG_COOLDOWN_MS) return;
    threatLogCooldown.set(key, now);
    logThreat(msg, isCritical);
}

function stopReplayMode() {
    if (replayTimer) {
        clearInterval(replayTimer);
        replayTimer = null;
    }
    if (replayMode) {
        replayMode = false;
        replayBtn.textContent = 'Replay Last 60s';
        logThreat('Replay complete. Returning to live telemetry.', false);
    }
}

function startReplay(frames, windowSeconds) {
    if (!Array.isArray(frames) || frames.length === 0) {
        logThreat('Replay unavailable: no events captured in requested window.', true);
        stopReplayMode();
        return;
    }

    stopReplayMode();
    replayMode = true;
    replayBtn.textContent = 'Stop Replay';
    statStatus.innerText = 'REPLAY MODE';
    statStatus.className = 'value warning';
    logThreat(`Replaying last ${windowSeconds}s (${frames.length} frames)`, false);

    let idx = 0;
    replayTimer = setInterval(() => {
        if (idx >= frames.length) {
            stopReplayMode();
            return;
        }
        processFlows(frames[idx].data, true);
        idx += 1;
    }, 100);
}

function requestReplay(seconds = 60) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        logThreat('Replay failed: backend stream is offline.', true);
        return;
    }
    ws.send(JSON.stringify({ type: 'replay_request', seconds }));
}

// 2. WebSocket Connection
let ws = null;
let hasConnected = false;
let wsEndpointIndex = 0;

const wsEndpoints = (() => {
    const host = window.location.hostname || 'localhost';
    if (window.location.protocol === 'https:') {
        return [
            `wss://${host}:8765`,
            'ws://127.0.0.1:8765',
            'ws://localhost:8765'
        ];
    }
    return [`ws://${host}:8765`, 'ws://127.0.0.1:8765', 'ws://localhost:8765'];
})();

function connectWebSocket() {
    const endpoint = wsEndpoints[wsEndpointIndex];
    statStatus.innerText = 'CONNECTING...';
    statStatus.className = 'value warning';
    ws = new WebSocket(endpoint);

    ws.onopen = () => {
        console.log(`[*] Connected to NetSpectre Backend Engine at ${endpoint}`);
        logThreat(`SYSTEM ONLINE. STREAM: ${endpoint}`, false);
        hasConnected = true;
        statStatus.innerText = 'SECURE';
        statStatus.className = 'value ok';
    };

    ws.onerror = (e) => {
        console.error(`WebSocket Error (${endpoint})`, e);
    };

    ws.onclose = () => {
        if (!hasConnected && wsEndpointIndex < wsEndpoints.length - 1) {
            wsEndpointIndex += 1;
            connectWebSocket();
            return;
        }
        hasConnected = false;
        statStatus.innerText = 'ENGINE OFFLINE';
        statStatus.className = 'value threat';
        // Auto-reconnect after 3 seconds
        wsEndpointIndex = 0;
        setTimeout(connectWebSocket, 3000);
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'flows') {
            if (replayMode) return;
            window.__latestTracePaths = msg.paths || {};
            processFlows(msg.data);
            return;
        }
        if (msg.type === 'replay_data') {
            startReplay(msg.data || [], msg.window_seconds || 60);
        }
    };
}

connectWebSocket();

replayBtn.addEventListener('click', () => {
    if (replayMode) {
        stopReplayMode();
        return;
    }
    requestReplay(60);
});

// 3. Flow Processing Logic
function processFlows(flows, isReplayFrame = false) {
    let newNodes = [];
    let newLinks = [];
    threatCount = 0;
    const sourceThreatState = new Map();
    const now = Date.now();
    const hostFrameMetrics = new Map();
    const pathLinks = [];
    const pathLinkSet = new Set();

    const ensureNode = (ip, props = {}) => {
        if (!nodeSet.has(ip)) {
            nodeSet.add(ip);
            newNodes.push({ id: ip, ...props });
        }
        nodeLastSeen.set(ip, now);
    };

    // Evaluate Global Threat State
    let maxRisk = 0;

    flows.forEach(f => {
        const src = f.src;
        const dst = f.dst;
        nodeLastSeen.set(src, now);
        nodeLastSeen.set(dst, now);

        const srcCtx = getContext(src);
        const dstCtx = getContext(dst);
        srcCtx.peers.add(dst);
        dstCtx.peers.add(src);
        srcCtx.dstPorts.add(f.dst_port);
        dstCtx.srcPorts.add(f.src_port);
        srcCtx.outbound += 1;
        dstCtx.inbound += 1;
        srcCtx.lastSeen = now;
        dstCtx.lastSeen = now;

        const duration = Math.max(0.1, Number(f.duration) || 0.1);
        const flowPps = (Number(f.packets) || 0) / duration;

        if (!hostFrameMetrics.has(src)) {
            hostFrameMetrics.set(src, { connections: 0, packetRate: 0, ports: new Set() });
        }
        if (!hostFrameMetrics.has(dst)) {
            hostFrameMetrics.set(dst, { connections: 0, packetRate: 0, ports: new Set() });
        }
        const srcMetrics = hostFrameMetrics.get(src);
        const dstMetrics = hostFrameMetrics.get(dst);
        srcMetrics.connections += 1;
        srcMetrics.packetRate += flowPps;
        srcMetrics.ports.add(f.dst_port);
        dstMetrics.packetRate += flowPps * 0.3;

        // Update tracking sets
        ensureNode(src, { isExternal: isExternalIp(src), role: deriveRole(src) });
        ensureNode(dst, { isExternal: isExternalIp(dst), role: deriveRole(dst) });

        // Determine link styling based on threat assessment
        let color = 'rgba(255, 255, 255, 0.2)';
        const packetRate = flowPps;
        let width = packetRate < 15 ? 0.5 : (packetRate < 80 ? 1.4 : 3.2);
        let opacity = 0.4;
        let particleSpeed = 0.004;
        let attackType = 'normal';
        const normalizedClass = (f.classification || 'normal').replace(/^remote_/, '');
        
        if (f.classification !== 'normal') {
            threatCount++;
            maxRisk = Math.max(maxRisk, f.risk_score);
            
            if (normalizedClass === 'syn_scan' || normalizedClass === 'port_sweep' || normalizedClass === 'scanner' || normalizedClass === 'unusual_port_activity' || normalizedClass === 'unexpected_pattern') {
                color = '#ffaa00'; // Pulsing yellow
                width = Math.max(width, 1.2);
                particleSpeed = 0.01;
                attackType = 'scan';
            } else if (normalizedClass === 'icmp_flood' || normalizedClass === 'dos' || normalizedClass === 'dos+scanner' || normalizedClass === 'traffic_spike') {
                color = '#ff3333'; // Thick red
                width = Math.max(width, 3.0);
                opacity = 0.8;
                particleSpeed = 0.03;
                attackType = 'flood';
            } else if (normalizedClass === 'dns_anomaly' || normalizedClass === 'exfiltration' || normalizedClass === 'c2_beacon') {
                color = '#00ff00'; // Neon green
                width = Math.max(width, 2.0);
                particleSpeed = 0.008;
                attackType = 'exfil';
            }

            // Threat highlight: severe events turn node red, others yellow.
            const previous = sourceThreatState.get(src) || { isAttacker: false, isAnomaly: false };
            if (f.risk_score >= 70 || normalizedClass === 'icmp_flood' || normalizedClass === 'dos' || normalizedClass === 'dos+scanner') {
                sourceThreatState.set(src, { isAttacker: true, isAnomaly: false });
            } else if (!previous.isAttacker) {
                sourceThreatState.set(src, { isAttacker: false, isAnomaly: true });
            }

            // Log threat events deterministically with cooldown.
            if (f.risk_score > 35) {
                const threatKey = `${f.classification}:${src}:${dst}`;
                const hopText = f.hops_estimate && f.hops_estimate > 0 ? ` (~${Math.round(f.hops_estimate)} hops)` : '';
                logThreatWithCooldown(
                    threatKey,
                    `[ALERT] ${f.classification.toUpperCase()} detected from ${src}${hopText}`,
                    f.classification.includes('dos') || f.classification.includes('flood')
                );
            }
        }

        newLinks.push({
            source: src,
            target: dst,
            color: color,
            width: width,
            opacity: opacity,
            particleSpeed: particleSpeed,
            attackType: attackType,
            packetRate: packetRate,
            value: f.bytes
        });
    });

    // Draw traceroute hop chains for external targets.
    const latestPaths = window.__latestTracePaths || {};
    const addPathLink = (a, b) => {
        const key = `${a}->${b}`;
        if (pathLinkSet.has(key)) return;
        pathLinkSet.add(key);
        pathLinks.push({
            source: a,
            target: b,
            color: 'rgba(106, 163, 255, 0.42)',
            width: 0.8,
            opacity: 0.28,
            particleSpeed: 0.003,
            attackType: 'normal',
            value: 1
        });
    };
    const flowsByTarget = new Map();
    flows.forEach(f => {
        const srcPrivate = !isExternalIp(f.src);
        const dstPrivate = !isExternalIp(f.dst);
        if (srcPrivate && !dstPrivate) {
            if (!flowsByTarget.has(f.dst)) flowsByTarget.set(f.dst, new Set());
            flowsByTarget.get(f.dst).add(f.src);
        } else if (!srcPrivate && dstPrivate) {
            if (!flowsByTarget.has(f.src)) flowsByTarget.set(f.src, new Set());
            flowsByTarget.get(f.src).add(f.dst);
        }
    });
    Object.entries(latestPaths).forEach(([target, hops]) => {
        if (!Array.isArray(hops) || hops.length === 0) return;
        const anchors = flowsByTarget.get(target);
        if (!anchors || anchors.size === 0) return;
        if (isPrivateIp(hops[0])) {
            userRouterIp = hops[0];
        }

        hops.forEach(hopIp => ensureNode(hopIp, { isExternal: true, role: 'router_hop', isPathHop: true }));
        ensureNode(target, { isExternal: isExternalIp(target), role: deriveRole(target) });

        anchors.forEach(anchor => {
            addPathLink(anchor, hops[0]);
            for (let i = 0; i < hops.length - 1; i++) {
                addPathLink(hops[i], hops[i + 1]);
            }
            addPathLink(hops[hops.length - 1], target);
        });
    });

    // Update graph data without losing physics momentum
    // Merge new nodes
    graphData.nodes = [...graphData.nodes, ...newNodes];

    // Keep graph size bounded for long-running sessions.
    graphData.nodes = graphData.nodes.filter(node => {
        const seenAt = nodeLastSeen.get(node.id) || 0;
        return (now - seenAt <= NODE_TTL_MS) || sourceThreatState.has(node.id);
    });
    if (graphData.nodes.length > MAX_NODES) {
        graphData.nodes.sort((a, b) => (nodeLastSeen.get(b.id) || 0) - (nodeLastSeen.get(a.id) || 0));
        graphData.nodes = graphData.nodes.slice(0, MAX_NODES);
    }
    nodeSet = new Set(graphData.nodes.map(node => node.id));
    for (const ip of Array.from(nodeLastSeen.keys())) {
        if (!nodeSet.has(ip)) {
            nodeLastSeen.delete(ip);
            nodeContext.delete(ip);
        }
    }

    // Apply node statuses after evaluating the entire batch.
    graphData.nodes.forEach(node => {
        const metrics = hostFrameMetrics.get(node.id);
        if (metrics && !isReplayFrame) {
            const stats = getHostStats(node.id);
            updateRollingStat(stats.cps, metrics.connections);
            updateRollingStat(stats.pps, metrics.packetRate);
            updateRollingStat(stats.ports, metrics.ports.size);
        }

        const stats = getHostStats(node.id);
        const cps = metrics ? metrics.connections : 0;
        const pps = metrics ? metrics.packetRate : 0;
        const portActivity = metrics ? metrics.ports.size : 0;
        const anomalyScore = Math.min(
            100,
            Math.max(0, zScore(stats.cps, cps)) * 20 +
            Math.max(0, zScore(stats.pps, pps)) * 20 +
            Math.max(0, zScore(stats.ports, portActivity)) * 20
        );

        const status = sourceThreatState.get(node.id);
        node.isUserRouter = Boolean((userRouterIp && node.id === userRouterIp) || isLikelyUserRouter(node.id));
        if (!node.isPathHop) {
            node.isAttacker = Boolean(status?.isAttacker);
            node.isAnomaly = Boolean(status?.isAnomaly) || (!node.isAttacker && anomalyScore >= ANOMALY_SCORE_THRESHOLD);
            node.isExternal = isExternalIp(node.id);
            node.role = deriveRole(node.id);
        } else {
            node.isAttacker = false;
            node.isAnomaly = false;
            node.isExternal = true;
            node.role = 'router_hop';
        }
        node.connections_per_second = cps;
        node.packet_rate = pps;
        node.port_activity = portActivity;
        node.anomaly_score = Math.round(anomalyScore);

        const fixed = fixedNodePosition(node);
        node.x = fixed.x;
        node.y = fixed.y;
        node.z = fixed.z;
        node.fx = fixed.x;
        node.fy = fixed.y;
        node.fz = fixed.z;
    });

    // We only keep nodes that are currently active (or we fade them out, but for now we keep them to maintain gravity)
    // Overwrite links because they are ephemeral
    graphData.links = [...newLinks, ...pathLinks].filter(link => nodeSet.has(link.source) && nodeSet.has(link.target));

    Graph.graphData(graphData);

    // Update HUD Metrics
    statFlows.innerText = flows.length;
    statThreats.innerText = threatCount;

    if (!isReplayFrame && now - lastFeedStatusAt > FEED_STATUS_INTERVAL_MS) {
        if (flows.length === 0) {
            logThreat('No live packets received. Check backend mode/interface/sudo.', true);
        } else {
            logThreat(`Live telemetry: ${flows.length} active flows`, false);
        }
        lastFeedStatusAt = now;
    }

    if (threatCount > 0) {
        statThreats.className = 'value threat';
        if (maxRisk > 50) {
            statStatus.innerText = 'CRIT: UNDER ATTACK';
            statStatus.className = 'value threat';
            document.getElementById('ui-layer').style.boxShadow = 'inset 0 0 50px rgba(255,0,0,0.2)';
        } else {
            statStatus.innerText = 'WARN: SUSPICIOUS';
            statStatus.className = 'value warning';
            document.getElementById('ui-layer').style.boxShadow = 'none';
        }
    } else {
        statThreats.className = 'value ok';
        statStatus.innerText = 'SECURE';
        statStatus.className = 'value ok';
        document.getElementById('ui-layer').style.boxShadow = 'none';
    }
}

// Window resize handling
window.addEventListener('resize', () => {
    Graph.width(window.innerWidth);
    Graph.height(window.innerHeight);
});
