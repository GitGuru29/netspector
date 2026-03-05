// NetSpectre Main Application Logic

// 1. Initialize 3D Force Graph
const elem = document.getElementById('3d-graph');
const Graph = ForceGraph3D()(elem)
    .backgroundColor('#050505')
    .nodeRelSize(4)
    .nodeAutoColorBy('group')
    .nodeResolution(16)
    .linkDirectionalParticles(2)
    .linkDirectionalParticleWidth(1.2)
    .linkDirectionalParticleSpeed(d => d.particleSpeed)
    .linkColor(d => d.color)
    .linkOpacity(d => d.opacity)
    .linkWidth(d => d.width)
    .enableNodeDrag(false)
    .nodeColor(node => {
        // Node coloring logic
        if (node.id.startsWith('185.') || node.id.startsWith('45.') || node.id.startsWith('91.')) return '#8800ff'; // External Threat
        if (node.isAttacker) return '#ff3333'; // Red
        if (node.isAnomaly) return '#ffaa00'; // Orange
        if (node.isExternal) return '#8800ff'; // Purple
        return '#00ffcc'; // Normal internal host
    })
    .onNodeClick(node => {
        // Aim camera
        const distance = 100;
        const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);
        Graph.cameraPosition(
            { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
            node, 
            3000
        );
    });

// Post-processing setup (Bloom) for that glowing hacker aesthetic
const { createBloomPass } = window; // If we add unreal bloom later, right now basic 3d-force-graph handles basic webgl

// State mapping
let graphData = { nodes: [], links: [] };
let nodeSet = new Set();
let threatCount = 0;

// Update HUD
const statFlows = document.getElementById('stat-flows');
const statThreats = document.getElementById('stat-threats');
const statStatus = document.getElementById('stat-status');
const threatLogs = document.getElementById('threat-logs');

function logThreat(msg, isCritical=false) {
    const li = document.createElement('li');
    li.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    if(isCritical) li.className = 'critical';
    threatLogs.prepend(li);
    if(threatLogs.children.length > 15) {
        threatLogs.removeChild(threatLogs.lastChild);
    }
}

// 2. WebSocket Connection
const ws = new WebSocket('ws://localhost:8765');
let hasConnected = false;

ws.onopen = () => {
    console.log('[*] Connected to NetSpectre Backend Engine');
    logThreat('SYSTEM ONLINE. AWAITING INTEL...', false);
    hasConnected = true;
};

ws.onerror = (e) => {
    console.error('WebSocket Error', e);
    if (!hasConnected) statStatus.innerText = 'ENGINE OFFLINE';
    statStatus.className = 'value threat';
};

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'flows') {
        const flows = msg.data;
        processFlows(flows);
    }
};

// 3. Flow Processing Logic
function processFlows(flows) {
    let newNodes = [];
    let newLinks = [];
    let currentNodes = new Set();
    let oldThreats = threatCount;
    threatCount = 0;
    
    // Evaluate Global Threat State
    let maxRisk = 0;

    flows.forEach(f => {
        const src = f.src;
        const dst = f.dst;
        currentNodes.add(src);
        currentNodes.add(dst);

        // Update tracking sets
        if(!nodeSet.has(src)) { nodeSet.add(src); newNodes.push({ id: src, isExternal: (src.startsWith('8.') || src.startsWith('1.') || src.startsWith('104.')) }); }
        if(!nodeSet.has(dst)) { nodeSet.add(dst); newNodes.push({ id: dst, isExternal: (dst.startsWith('8.') || dst.startsWith('1.') || dst.startsWith('104.')) }); }

        // Determine link styling based on threat assessment
        let color = 'rgba(255, 255, 255, 0.2)'; // Thin white -> normal
        let width = 0.5;
        let opacity = 0.4;
        let particleSpeed = 0.004;
        
        if (f.classification !== 'normal') {
            threatCount++;
            maxRisk = Math.max(maxRisk, f.risk_score);
            
            if (f.classification === 'scanner') {
                color = '#ffaa00'; // Pulsing yellow
                width = 1.0;
                particleSpeed = 0.01;
            } else if (f.classification === 'dos' || f.classification === 'dos+scanner') {
                color = '#ff3333'; // Thick red
                width = 3.0;
                opacity = 0.8;
                particleSpeed = 0.03;
                
                // Set node attacker status
                const sourceNode = graphData.nodes.find(n => n.id === src);
                if(sourceNode) sourceNode.isAttacker = true;
                
            } else if (f.classification === 'exfiltration' || f.classification === 'c2_beacon') {
                color = '#00ff00'; // Neon green
                width = 2.0;
                particleSpeed = 0.008;
            }
            
            // Log new threats (naive implementation, logs repeatedly, but good for visual effect)
            if (f.risk_score > 60 && Math.random() < 0.05) { 
                logThreat(`${f.classification.toUpperCase()} DETECTED from ${src} to ${dst}`, f.classification.includes('dos'));
            }
        } else {
             // Clean node status if normal
             const sourceNode = graphData.nodes.find(n => n.id === src);
             if(sourceNode) {
                 sourceNode.isAttacker = false;
                 sourceNode.isAnomaly = false;
             }
        }

        newLinks.push({
            source: src,
            target: dst,
            color: color,
            width: width,
            opacity: opacity,
            particleSpeed: particleSpeed,
            value: f.bytes
        });
    });

    // Update graph data without losing physics momentum
    // Merge new nodes
    graphData.nodes = [...graphData.nodes, ...newNodes];
    
    // We only keep nodes that are currently active (or we fade them out, but for now we keep them to maintain gravity)
    // Overwrite links because they are ephemeral
    graphData.links = newLinks;
    
    Graph.graphData(graphData);

    // Update HUD Metrics
    statFlows.innerText = flows.length;
    statThreats.innerText = threatCount;
    
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
