// NetSpectre Main Application Logic

// 1. Initialize 3D Force Graph
const elem = document.getElementById('3d-graph');
const Graph = ForceGraph3D()(elem)
    .backgroundColor('#050505')
    .nodeRelSize(4)
    .nodeAutoColorBy('group')
    .nodeResolution(16)
    .nodeLabel(node => `${node.id}\n${(node.role || 'internal_host').replace('_', ' ')}`)
    .nodeVal(node => {
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
    .nodeColor(node => {
        // Priority coloring: attacker > suspicious > external > internal.
        if (node.isAttacker) return '#ff3333'; // Red
        if (node.isAnomaly) return '#ffaa00'; // Orange
        if (node.isExternal) return '#8b5cf6'; // Purple external internet
        return '#2f80ff'; // Blue internal host
    })
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
            const flows = msg.data;
            processFlows(flows);
        }
    };
}

connectWebSocket();

// 3. Flow Processing Logic
function processFlows(flows) {
    let newNodes = [];
    let newLinks = [];
    threatCount = 0;
    const sourceThreatState = new Map();
    const now = Date.now();

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

        // Update tracking sets
        if (!nodeSet.has(src)) { nodeSet.add(src); newNodes.push({ id: src, isExternal: isExternalIp(src), role: deriveRole(src) }); }
        if (!nodeSet.has(dst)) { nodeSet.add(dst); newNodes.push({ id: dst, isExternal: isExternalIp(dst), role: deriveRole(dst) }); }

        // Determine link styling based on threat assessment
        let color = 'rgba(255, 255, 255, 0.2)'; // Thin white -> normal
        let width = 0.5;
        let opacity = 0.4;
        let particleSpeed = 0.004;
        let attackType = 'normal';
        
        if (f.classification !== 'normal') {
            threatCount++;
            maxRisk = Math.max(maxRisk, f.risk_score);
            
            if (f.classification === 'syn_scan' || f.classification === 'port_sweep' || f.classification === 'scanner') {
                color = '#ffaa00'; // Pulsing yellow
                width = 1.0;
                particleSpeed = 0.01;
                attackType = 'scan';
            } else if (f.classification === 'icmp_flood' || f.classification === 'dos' || f.classification === 'dos+scanner') {
                color = '#ff3333'; // Thick red
                width = 3.0;
                opacity = 0.8;
                particleSpeed = 0.03;
                attackType = 'flood';
            } else if (f.classification === 'dns_anomaly' || f.classification === 'exfiltration' || f.classification === 'c2_beacon') {
                color = '#00ff00'; // Neon green
                width = 2.0;
                particleSpeed = 0.008;
                attackType = 'exfil';
            }

            // Track per-source threat state so normal flows don't clear active attacker flags.
            const previous = sourceThreatState.get(src) || { isAttacker: false, isAnomaly: false };
            if (f.classification === 'icmp_flood' || f.classification === 'dos' || f.classification === 'dos+scanner') {
                sourceThreatState.set(src, { isAttacker: true, isAnomaly: false });
            } else if (!previous.isAttacker) {
                sourceThreatState.set(src, { isAttacker: false, isAnomaly: true });
            }

            // Log threat events deterministically with cooldown.
            if (f.risk_score > 35) {
                const threatKey = `${f.classification}:${src}:${dst}`;
                logThreatWithCooldown(
                    threatKey,
                    `${f.classification.toUpperCase()} DETECTED from ${src} to ${dst}`,
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
            value: f.bytes
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
        const status = sourceThreatState.get(node.id);
        node.isAttacker = Boolean(status?.isAttacker);
        node.isAnomaly = Boolean(status?.isAnomaly);
        node.isExternal = isExternalIp(node.id);
        node.role = deriveRole(node.id);

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
    graphData.links = newLinks.filter(link => nodeSet.has(link.source) && nodeSet.has(link.target));

    Graph.graphData(graphData);

    // Update HUD Metrics
    statFlows.innerText = flows.length;
    statThreats.innerText = threatCount;

    if (now - lastFeedStatusAt > FEED_STATUS_INTERVAL_MS) {
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
