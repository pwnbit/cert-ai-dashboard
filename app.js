// Simulation State
let activeAlertsCount = 0;
let approvedBlocksCount = 0;
let rejectedProposalsCount = 0;
let speedMultiplier = 1;
let isSimulating = false;

// Incident Data Templates
const alertsData = {
    ddos: {
        title: "DDOS_HIGH_TRAFFIC_ALERT",
        severity: "CRITICAL",
        source: "Datadog SIEM Rule #492",
        log: "Timestamp: 2026-07-15T00:05:10, Protocol: TCP/SYN, Src: 198.51.100.42, Dst: 10.0.1.200 (Web Gateway), Pkts/Sec: 145,200",
        ioc: "198.51.100.42",
        iocType: "IP Address",
        queryText: "SELECT count(*) FROM fw_logs WHERE src_ip = '198.51.100.42' AND status = 'blocked'",
        queryResult: "History Query: 2 similar high-traffic spikes from this IP in the past 7 days. Total blocks: 4.",
        tiDescription: "Known Mirai Botnet C2 Node. Registered in multiple threat feeds.",
        validatorRule: "Checking Destination Asset mapping...",
        validatorVerdict: "APPROVED: Target IP is an external botnet. No internal dependencies mapped. Business Impact: ZERO. Fire containment rules.",
        slackMsg: "Containment active. Inbound Firewall block rule pushed to Edge Routers."
    },
    bruteforce: {
        title: "BRUTE_FORCE_SSH_ATTEMPT",
        severity: "WARNING",
        source: "Datadog SIEM Rule #108",
        log: "Timestamp: 2026-07-15T00:05:18, Service: SSH, Src: 8.8.8.8, Target: 10.20.45.12 (DB Prod), Event: 24 failed logins",
        ioc: "8.8.8.8",
        iocType: "IP Address",
        queryText: "SELECT hostname, type FROM asset_db WHERE ip = '8.8.8.8'",
        queryResult: "Asset Check: IP 8.8.8.8 matches 'Google Public DNS' (Shared Global DNS Infrastructure).",
        tiDescription: "Safe IP. Public DNS resolver. Zero threat score. (Possible configuration error or spoofing detected)",
        validatorRule: "Evaluating Business Dependency impact...",
        validatorVerdict: "REJECTED: WARNING! Block proposal targets 8.8.8.8 (Google Public DNS). Blocking this IP will cause CRITICAL DNS RESOLUTION OUTAGES across the entire enterprise network. Operation canceled. Human analyst intervention required.",
        slackMsg: "Block proposal REJECTED by Validator. Prevented massive network outage. Dispatched ticket to network team to check configuration."
    },
    malware: {
        title: "MALWARE_BEACONING_DETECTED",
        severity: "CRITICAL",
        source: "Datadog SIEM Rule #771",
        log: "Timestamp: 2026-07-15T00:05:25, Protocol: DNS Query, Src: 10.0.50.84 (HR-Laptop-02), Domain: malicious-beacon.ru",
        ioc: "malicious-beacon.ru",
        iocType: "Domain Name",
        queryText: "SELECT * FROM endpoint_telemetry WHERE host = 'HR-Laptop-02' ORDER BY timestamp DESC LIMIT 5",
        queryResult: "Telemetry: Executable 'svchost_temp.exe' spawned by user 'hr_recruiter'. Process established network hook.",
        escalationReason: "Suspicious obfuscated signature found in process dump. Escalate to Tier 2 for malware static analysis.",
        t2AnalysisLog: "Tier 2 static analysis: Detected Hermit Ransomware DGA pattern. Signature: HERMIT_V4_VARIANT.",
        tiDescription: "Malicious Russian DGA Domain connected to Hermit Ransomware control infrastructure.",
        validatorRule: "Auditing Endpoint Isolation impact...",
        validatorVerdict: "APPROVED: Target host is HR-Laptop-02 (non-critical asset). Isolated to Prevent lateral movement. Domain blocked at DNS forwarder. Business Impact: LOW.",
        slackMsg: "Containment active. Endpoint isolated from VLAN 50. DNS forwarder rules updated to sinkhole domain."
    }
};

// Clock Setup
function updateClock() {
    const clockEl = document.getElementById('real-timestamp');
    if (!clockEl) return;
    
    setInterval(() => {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        
        clockEl.textContent = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }, 1000);
}

// Speed Control
const speedButtons = document.querySelectorAll('.speed-btn');
speedButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        speedButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        speedMultiplier = parseInt(btn.getAttribute('data-speed'), 10);
        logSystem(`[SYSTEM] Simulation speed adjusted to ${speedMultiplier}x`);
    });
});

// Logs System
const terminalOutput = document.getElementById('terminal-output');
function logTerminal(message, type = 'system-msg') {
    const line = document.createElement('div');
    line.className = `log-line ${type}`;
    
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    line.innerHTML = `<span style="color:#6b7280; font-size:10px;">[${timeStr}]</span> ${message}`;
    
    terminalOutput.appendChild(line);
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function logSystem(msg) { logTerminal(msg, 'system-msg'); }
function logCollector(msg) { logTerminal(`[Collector Agent] ${msg}`, 'collector-msg'); }
function logDDAgent(msg) { logTerminal(`[Datadog Agent] ${msg}`, 'dd-agent-msg'); }
function logAnalyst(msg) { logTerminal(`[T1 Analyst AI] ${msg}`, 'analyst-msg'); }
function logTier2(msg) { logTerminal(`[T2 Analyst AI] ${msg}`, 'tier2-msg'); }
function logTI(msg) { logTerminal(`[TI Agent] ${msg}`, 'ti-msg'); }
function logValidator(msg) { logTerminal(`[Validator Agent] ${msg}`, 'validator-msg'); }
function logSuccess(msg) { logTerminal(`[VERDICT APPROVED] ${msg}`, 'success-msg'); }
function logFailure(msg) { logTerminal(`[VERDICT REJECTED] ${msg}`, 'error-msg'); }
function logWarning(msg) { logTerminal(`[WARNING] ${msg}`, 'warning-msg'); }

function clearLogs() {
    terminalOutput.innerHTML = '<div class="log-line system-msg">[SYSTEM] Log cleared. Listening for alerts...</div>';
}

// SVG Laser Drawing
function getCenterCoords(elementId) {
    const el = document.getElementById(elementId);
    const container = document.querySelector('.office-map-container');
    if (!el || !container) return { x: 0, y: 0 };
    
    const rect = el.getBoundingClientRect();
    const cRect = container.getBoundingClientRect();
    
    return {
        x: rect.left - cRect.left + (rect.width / 2),
        y: rect.top - cRect.top + (rect.height / 2)
    };
}

function drawLaser(startId, endId, pathId, colorClass) {
    const start = getCenterCoords(startId);
    const end = getCenterCoords(endId);
    const path = document.getElementById(pathId);
    
    if (!path) return;
    
    path.setAttribute('d', `M ${start.x} ${start.y} L ${end.x} ${end.y}`);
    path.className.baseVal = `flow-line active ${colorClass}`;
}

function removeLaser(pathId) {
    const path = document.getElementById(pathId);
    if (path) {
        path.className.baseVal = 'flow-line';
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms / speedMultiplier));
}

function showSpeech(agentId, text, duration = 3200) {
    const bubble = document.getElementById(`${agentId}-speech`);
    if (!bubble) return;
    bubble.textContent = text;
    bubble.classList.add('active');
    
    setTimeout(() => {
        bubble.classList.remove('active');
    }, duration / speedMultiplier);
}

// CORE SIMULATION LOGIC
async function triggerAlert(type) {
    if (isSimulating) {
        logWarning("Another incident simulation is currently active. Please wait.");
        return;
    }
    
    const alert = alertsData[type];
    if (!alert) return;
    
    isSimulating = true;
    document.getElementById('simulation-status').textContent = "SIMULATING INCIDENT";
    document.getElementById('simulation-status').parentElement.style.color = "var(--color-danger)";
    document.getElementById('simulation-status').parentElement.style.borderColor = "rgba(239,68,68,0.2)";
    document.getElementById('simulation-status').parentElement.style.background = "rgba(239,68,68,0.1)";

    activeAlertsCount++;
    document.getElementById('metric-alerts').textContent = activeAlertsCount;
    document.getElementById('metric-threat-level').textContent = "INCIDENT ACTIVE";
    document.getElementById('metric-threat-level').className = "metric-val text-danger";
    
    try {
        // --- STEP 1: Datadog SIEM Ingestion ---
        logSystem(`--- Incident Triggered: ${alert.title} ---`);
        const ddNode = document.getElementById('node-datadog');
        ddNode.classList.add('alerting');
        document.getElementById('datadog-badge').textContent = "ALERT TRIGGERED";
        
        logSystem(`Datadog Webhook Raw Payload:\n${JSON.stringify({
            rule: alert.source,
            severity: alert.severity,
            raw_log: alert.log
        }, null, 2)}`);
        
        await delay(1500);

        // --- STEP 2: Collector Normalizing ---
        drawLaser('node-datadog', 'node-collector', 'flow-path-1', 'to-collector');
        const collectorNode = document.getElementById('node-collector');
        collectorNode.classList.add('working');
        document.getElementById('collector-status').textContent = "NORMALIZING";
        showSpeech('collector', "경보 데이터 감지. 원본 JSON 파싱 및 전규화 작업 중...");
        logCollector(`Ingested alert: [${alert.title}]`);
        logCollector(`Normalizing telemetry payload fields to structured JSON.`);
        
        await delay(1800);
        collectorNode.classList.remove('working');
        collectorNode.classList.add('success');
        document.getElementById('collector-status').textContent = "STANDBY";
        removeLaser('flow-path-1');

        // --- STEP 3: T1 Analyst Ingests ---
        drawLaser('node-collector', 'node-analyst', 'flow-path-1', 'to-analyst');
        const analystNode = document.getElementById('node-analyst');
        analystNode.classList.add('working');
        document.getElementById('analyst-status').textContent = "INITIAL TRIAGE";
        showSpeech('analyst', "Alert 데이터 수령. 우선순위 결정 및 Datadog Agent를 통한 연관 로그 분석 개시.");
        logAnalyst(`Initiated alert triage for: ${alert.title}`);
        
        await delay(2000);
        removeLaser('flow-path-1');

        // --- STEP 4: T1 Analyst ➡️ Datadog Agent (Query Logs) ---
        drawLaser('node-analyst', 'node-dd-agent', 'flow-path-1', 'to-dd-agent');
        const ddAgentNode = document.getElementById('node-dd-agent');
        ddAgentNode.classList.add('working');
        document.getElementById('dd-agent-status').textContent = "LOG QUERYING";
        showSpeech('dd-agent', `보안 관제 데이터베이스에서 IoC [${alert.ioc}] 에 대한 과거 이력/연관 텔레메트리 조회 중...`);
        logDDAgent(`Executing log search query: "${alert.queryText}"`);
        
        await delay(2200);
        logDDAgent(`Query complete. Result: ${alert.queryResult}`);
        ddAgentNode.classList.remove('working');
        ddAgentNode.classList.add('success');
        document.getElementById('dd-agent-status').textContent = "IDLE";
        removeLaser('flow-path-1');

        // --- STEP 5: Datadog Agent ➡️ T1 Analyst (Return Query Results) ---
        drawLaser('node-dd-agent', 'node-analyst', 'flow-path-1', 'to-analyst');
        analystNode.classList.add('working');
        document.getElementById('analyst-status').textContent = "CORRELATING";
        showSpeech('analyst', "연관 로그 확인 완료. 위협 강도를 판정하기 위해 외부 Threat Intel 검토를 수행합니다.");
        logAnalyst(`Analyzing query telemetry results: "${alert.queryResult}"`);
        
        await delay(2000);
        removeLaser('flow-path-1');

        // Escalation Check Branch (Malware Beacon Scenario)
        let activeAnalystNode = 'node-analyst';
        let activeAnalystStatus = 'analyst-status';
        let isEscalated = false;

        if (alert.escalationReason) {
            isEscalated = true;
            logAnalyst(`[Escalation Required] ${alert.escalationReason}`);
            showSpeech('analyst', "난독화 프로세스 및 감염 단말 격리가 필요합니다. Tier 2 상위 분석가에게 에스컬레이션 요청.");
            
            // --- STEP 5a: T1 ➡️ T2 Escalation ---
            drawLaser('node-analyst', 'node-tier2-analyst', 'flow-path-2', 'to-tier2');
            analystNode.classList.remove('working');
            analystNode.classList.add('success');
            document.getElementById('analyst-status').textContent = "ESCALATED";
            
            const tier2Node = document.getElementById('node-tier2-analyst');
            tier2Node.classList.add('working');
            document.getElementById('tier2-analyst-status').textContent = "DEEP ANALYSIS";
            showSpeech('tier2-analyst', "에스컬레이션 인계. 감염 호스트 정보 분석 및 정적 시그니처 정밀 검사 개시.");
            logTier2(`Received escalated incident. Reason: ${alert.escalationReason}`);
            
            await delay(2500);
            logTier2(alert.t2AnalysisLog);
            removeLaser('flow-path-2');
            
            activeAnalystNode = 'node-tier2-analyst';
            activeAnalystStatus = 'tier2-analyst-status';
        }

        // --- STEP 6: TI Expert Query ---
        drawLaser(activeAnalystNode, 'node-ti', 'flow-path-1', 'to-ti');
        const tiNode = document.getElementById('node-ti');
        tiNode.classList.add('working');
        document.getElementById('ti-status').textContent = "REPUTATION QUERY";
        showSpeech('ti', `인텔리전스 데이터베이스에서 "${alert.ioc}" 평판 정보 크로스체크 중...`);
        logTI(`Threat intel lookup request for: ${alert.ioc}`);
        
        await delay(2300);
        logTI(`Lookup Result: ${alert.tiDescription}`);
        tiNode.classList.remove('working');
        tiNode.classList.add('success');
        document.getElementById('ti-status').textContent = "COMPLETED";
        removeLaser('flow-path-1');

        // --- STEP 7: TI Expert ➡️ Analyst ---
        drawLaser('node-ti', activeAnalystNode, 'flow-path-1', 'to-analyst');
        document.getElementById(activeAnalystStatus).textContent = "DECISION MAKING";
        if (isEscalated) {
            logTier2(`Threat validation received: ${alert.tiDescription}. Formulating mitigation rules.`);
            showSpeech('tier2-analyst', "TI 검증 완료. 침해사고 대응 지침에 따라 차단안을 작성하고 Validator 승인을 요청합니다.");
        } else {
            logAnalyst(`Threat validation received: ${alert.tiDescription}. Formulating mitigation rules.`);
            showSpeech('analyst', "TI 검증 완료. 차단 대응조치를 생성하여 Validator Agent에게 영향도 검토를 요청합니다.");
        }
        
        await delay(2000);
        removeLaser('flow-path-1');

        // --- STEP 8: Analyst ➡️ Validator Agent (Audit & Logic Check) ---
        drawLaser(activeAnalystNode, 'node-validator', 'flow-path-1', 'to-validator');
        const validatorNode = document.getElementById('node-validator');
        validatorNode.classList.add('working');
        document.getElementById('validator-status').textContent = "AUDITING IMPACT";
        showSpeech('validator', `최종 제안된 조치의 비즈니스 영향도 평가 중: [${alert.validatorRule}]`);
        logValidator(`Starting critical impact audit... Target: [${alert.ioc}]`);
        logValidator(`Assessment: ${alert.validatorVerdict}`);
        
        await delay(2600);
        
        let decisionApproved = true;
        if (type === 'bruteforce') {
            decisionApproved = false; // Google DNS block should be REJECTED!
        }
        
        removeLaser('flow-path-1');

        // --- STEP 9: Validator Agent Verdict & Action ---
        if (decisionApproved) {
            // Case: Approved
            approvedBlocksCount++;
            document.getElementById('metric-blocks').textContent = approvedBlocksCount;
            validatorNode.classList.remove('working');
            validatorNode.classList.add('success');
            document.getElementById('validator-status').textContent = "APPROVED";
            showSpeech('validator', "검증 완료: 서비스 영향도 검토결과 안전함. 차단 조치안 최종 승인!");
            logSuccess(`Validation Approved. Safe to execute mitigation.`);
            
            // Draw Laser to Slack
            drawLaser('node-validator', 'node-analyst', 'flow-path-1', 'to-analyst');
            await delay(1200);
            removeLaser('flow-path-1');
            
            postToSlack(alert, 'APPROVED', isEscalated);
        } else {
            // Case: Rejected (Critical outage protection)
            rejectedProposalsCount++;
            document.getElementById('metric-rejects').textContent = rejectedProposalsCount;
            validatorNode.classList.remove('working');
            validatorNode.classList.add('danger-state');
            document.getElementById('validator-status').textContent = "REJECTED";
            showSpeech('validator', "🚨 검증 거부! 중요 공용 IP 차단은 전사 네트워크 장애를 초래합니다! 즉각 조치 반려.", 3500);
            logFailure(`Validation REJECTED. Dangerous asset block detected.`);
            
            // Draw Warning Line back
            drawLaser('node-validator', 'node-analyst', 'flow-path-1', 'to-analyst');
            await delay(1200);
            removeLaser('flow-path-1');
            
            postToSlack(alert, 'REJECTED', isEscalated);
        }

        await delay(2500);

        // Reset
        logSystem(`--- Incident Handling Flow Completed ---`);
        resetSimulationState();

    } catch (e) {
        logTerminal(`[ERROR] Simulation failed: ${e.message}`, 'error-msg');
        resetSimulationState();
    }
}

function resetSimulationState() {
    isSimulating = false;
    document.getElementById('simulation-status').textContent = "SYSTEM ACTIVE";
    document.getElementById('simulation-status').parentElement.style.color = "var(--color-safe)";
    document.getElementById('simulation-status').parentElement.style.borderColor = "rgba(16, 185, 129, 0.2)";
    document.getElementById('simulation-status').parentElement.style.background = "rgba(16, 185, 129, 0.1)";
    
    // Clear all lasers
    removeLaser('flow-path-1');
    removeLaser('flow-path-2');
    removeLaser('flow-path-3');
    
    // Reset nodes
    document.getElementById('node-datadog').classList.remove('alerting');
    document.getElementById('datadog-badge').textContent = "STANDBY";
    
    const nodes = [
        'node-collector', 'node-dd-agent', 'node-analyst', 
        'node-tier2-analyst', 'node-ti', 'node-validator'
    ];
    nodes.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.className = 'office-node agent-node'; // Reset classes
            const statusEl = el.querySelector('.agent-status');
            if (statusEl) {
                if (id === 'node-tier2-analyst') statusEl.textContent = "STANDBY";
                else statusEl.textContent = "IDLE";
            }
        }
    });
    
    document.getElementById('metric-threat-level').textContent = "MONITORING";
    document.getElementById('metric-threat-level').className = "metric-val text-safe";
}

function postToSlack(alert, status, isEscalated) {
    const slackFeed = document.getElementById('slack-message-feed');
    if (!slackFeed) return;
    
    const emptyMsg = slackFeed.querySelector('.slack-empty-msg');
    if (emptyMsg) {
        emptyMsg.remove();
    }
    
    const card = document.createElement('div');
    const severityClass = alert.severity === 'CRITICAL' ? 'severity-critical' : 'severity-warning';
    
    const date = new Date();
    const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    if (status === 'APPROVED') {
        card.className = `slack-msg-card ${severityClass}`;
        card.innerHTML = `
            <div class="slack-msg-title">
                <span>🔴 [AUTOMATED BLOCK PUSHED] ${alert.title}</span>
                <span style="color:#6b7280; font-weight:normal; font-size:10px; margin-left:auto;">${timeStr}</span>
            </div>
            <div class="slack-msg-body">
                <strong>Verdict:</strong> True Positive | Validator Approved ✅<br>
                <strong>Target IoC:</strong> <code>${alert.ioc}</code> (${alert.iocType})<br>
                <strong>Mitigation Log:</strong> ${alert.slackMsg}<br>
                <strong>Impact Audit:</strong> ${alert.validatorVerdict}
            </div>
            <div class="slack-msg-meta">
                Analyst: ${isEscalated ? 'Tier 2 AI (Escalated)' : 'Tier 1 AI'} | Auditor: Validator Agent v1.0
            </div>
        `;
    } else {
        card.className = 'slack-msg-card rejected';
        card.innerHTML = `
            <div class="slack-msg-title" style="color:var(--color-warning);">
                <span>⚠️ [MITIGATION BLOCK BLOCKED] ${alert.title}</span>
                <span style="color:#6b7280; font-weight:normal; font-size:10px; margin-left:auto;">${timeStr}</span>
            </div>
            <div class="slack-msg-body">
                <strong style="color:var(--color-warning);">Verdict:</strong> Alert False Positive / Dangerous Block Blocked ❌<br>
                <strong>Requested IoC:</strong> <code>${alert.ioc}</code> (${alert.iocType})<br>
                <strong>Validator Log:</strong> <span style="color:#fca5a5;">${alert.validatorVerdict}</span><br>
                <strong>Action:</strong> Automated firewall block aborted. Log details dispatched to Security Operations team.
            </div>
            <div class="slack-msg-meta">
                Analyst: Tier 1 AI | Auditor: Validator Agent v1.0 (Critical Outage Protection)
            </div>
        `;
    }
    
    slackFeed.insertBefore(card, slackFeed.firstChild);
    slackFeed.scrollTop = 0;
}

window.addEventListener('DOMContentLoaded', () => {
    updateClock();
    logSystem("All agent sub-routines loaded and online.");
    
    // Periodic coordinate update to keep lines aligned
    setInterval(() => {
        // Redraw laser coordinates if active
        // Normally handled during transitions, but this ensures resize handles well
    }, 1000);
});
