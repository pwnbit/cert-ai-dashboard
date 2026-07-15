// Simulation State
let activeAlertsCount = 0;
let approvedBlocksCount = 0;
let rejectedProposalsCount = 0;
let speedMultiplier = 1;
let isSimulating = false;

// Incident Data Templates (Korean Version)
const alertsData = {
    ddos: {
        title: "DDOS_대용량_트래픽_경보",
        severity: "CRITICAL",
        source: "Datadog SIEM Rule #492 (임계치 초과)",
        log: "발생시각: 2026-07-15T00:05:10, 프로토콜: TCP/SYN, 출발지: 198.51.100.42, 목적지: 10.0.1.200 (웹 게이트웨이), 초당패킷수: 145,200, 전송량: 1.2GB/min",
        ioc: "198.51.100.42",
        iocType: "IP 주소",
        queryText: "SELECT count(*) FROM fw_logs WHERE src_ip = '198.51.100.42' AND status = 'blocked'",
        queryResult: "방화벽 로그 조회: 해당 IP에서 최근 7일간 2회의 대용량 트래픽 급증 이력 확인됨. 누적 차단 횟수: 4회.",
        tiDescription: "알려진 Mirai 봇넷 C2 노드. 다수의 해외 블랙리스트 및 위협 피드에 등록됨.",
        validatorRule: "목적지 내부 자산 영향도 평가 중...",
        validatorVerdict: "승인(APPROVED): 차단 대상 IP는 외부 봇넷 C2 서버이며, 내부 상용 API 게이트웨이 및 주요 서비스 자산과 연동 관계 없음. 차단 시 비즈니스 영향도: 없음. 방화벽 차단 명령 하달.",
        slackMsg: "자동 차단 조치 활성화. Edge 라우터 방화벽에 해당 IP에 대한 인바운드 차단(Drop) 룰 적용 완료."
    },
    bruteforce: {
        title: "BRUTE_FORCE_SSH_대입공격_감지",
        severity: "WARNING",
        source: "Datadog SIEM Rule #108 (로그인 실패 임계치)",
        log: "발생시각: 2026-07-15T00:05:18, 서비스: SSH, 출발지: 8.8.8.8, 목적지: 10.20.45.12 (DB Prod), 내용: 10초 이내에 root 계정 로그인 실패 24회 발생",
        ioc: "8.8.8.8",
        iocType: "IP 주소",
        queryText: "SELECT hostname, type FROM asset_db WHERE ip = '8.8.8.8'",
        queryResult: "자산 데이터베이스 조회: IP 8.8.8.8은 사내 공용 자산인 'Google Public DNS' (외부 DNS 쿼리용 공용 인프라)와 일치함.",
        tiDescription: "신뢰할 수 있는 공용 IP 주소. 구글 퍼블릭 DNS 리졸버. 위협 점수: 0 (설정 오류 혹은 IP 위조/스푸핑 가능성 존재)",
        validatorRule: "비즈니스 서비스 의존성 파급도 평가 중...",
        validatorVerdict: "반려(REJECTED): 경고! 차단 제안된 IP는 8.8.8.8 (Google Public DNS)입니다. 이 IP를 방화벽에서 일괄 차단할 경우 사내 모든 아웃바운드 인터넷 도메인 해석이 불가능해져 전사적 인터넷 장애(DNS Outage)를 유발합니다. 차단 조치를 긴급 취소하고, 보안 관제실(SOC) 담당자의 오설정 확인 조치(Jira 티켓 발행)로 우회합니다.",
        slackMsg: "차단 제안 반려됨(Validator 차단). 전사적 서비스 장애 유발 위험 방지. 네트워크 팀에 포트 오설정 및 스푸핑 여부 확인 티켓 자동 발송."
    },
    malware: {
        title: "악성_코드_비콘_통신_감지",
        severity: "CRITICAL",
        source: "Datadog SIEM Rule #771 (이상 도메인 질의)",
        log: "발생시각: 2026-07-15T00:05:25, 프로토콜: DNS 쿼리, 출발지: 10.0.50.84 (인사팀 HR-Laptop-02), 대상 도메인: malicious-beacon.ru",
        ioc: "malicious-beacon.ru",
        iocType: "도메인 이름",
        queryText: "SELECT * FROM endpoint_telemetry WHERE host = 'HR-Laptop-02' ORDER BY timestamp DESC LIMIT 5",
        queryResult: "단말 텔레메트리 조회: 사용자 'hr_recruiter'에 의해 의심스러운 임시 파일 'svchost_temp.exe'가 실행되었으며, 내부 프로세스 네트워크 후킹 감지됨.",
        escalationReason: "프로세스 메모리 덤프에서 고도로 난독화된 서명 및 DGA 패턴 감지. 심층 악성코드 분석 및 단말 격리를 위해 Tier 2 상위 분석가 에이전트에게 긴급 에스컬레이션 진행.",
        t2AnalysisLog: "Tier 2 정밀 정적 분석 수행: Hermit 랜섬웨어 변종 DGA 시그니처 매칭 완료. 서명 코드: HERMIT_V4_VARIANT. 내부 전파 위험 존재.",
        tiDescription: "악성 러시아 DGA 도메인. Hermit 랜섬웨어의 Command & Control (C2) 서버 인프라로 최종 확인됨.",
        validatorRule: "단말 격리 및 서비스 영향성 감사 중...",
        validatorVerdict: "승인(APPROVED): 격리 대상 호스트는 HR-Laptop-02 (비공용 인사팀 단말)입니다. 내부 망 전파 방지를 위해 즉각적인 네트워크 격리가 안전하며, 도메인은 사내 서비스와 무관하여 DNS 서버 차단 무해함. 비즈니스 영향도: 낮음.",
        slackMsg: "격리 및 차단 조치 활성화. VLAN 50 보안 스위치에서 해당 단말 포트 차단(격리). 사내 DNS DNS Forwarder에 해당 도메인 싱크홀(Sinkhole) 처리 완료."
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
        logSystem(`[시스템] 시뮬레이션 속도가 ${speedMultiplier}배속으로 변경되었습니다.`);
    });
});

// Logs System (Korean)
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
function logCollector(msg) { logTerminal(`[Collector 에이전트] ${msg}`, 'collector-msg'); }
function logDDAgent(msg) { logTerminal(`[Datadog 에이전트] ${msg}`, 'dd-agent-msg'); }
function logAnalyst(msg) { logTerminal(`[T1 분석 에이전트] ${msg}`, 'analyst-msg'); }
function logTier2(msg) { logTerminal(`[T2 분석 에이전트] ${msg}`, 'tier2-msg'); }
function logTI(msg) { logTerminal(`[TI 에이전트] ${msg}`, 'ti-msg'); }
function logValidator(msg) { logTerminal(`[Validator 에이전트] ${msg}`, 'validator-msg'); }
function logSuccess(msg) { logTerminal(`[최종 검증 승인] ${msg}`, 'success-msg'); }
function logFailure(msg) { logTerminal(`[최종 검증 반려] ${msg}`, 'error-msg'); }
function logWarning(msg) { logTerminal(`[경고] ${msg}`, 'warning-msg'); }

function clearLogs() {
    terminalOutput.innerHTML = '<div class="log-line system-msg">[시스템] 로그가 초기화되었습니다. 웹훅 수신 대기 중...</div>';
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
        logWarning("이미 진행 중인 침해사고 대응 시뮬레이션이 있습니다. 완료될 때까지 기다려 주세요.");
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
    document.getElementById('metric-threat-level').textContent = "경보 상황 활성화";
    document.getElementById('metric-threat-level').className = "metric-val text-danger";
    
    try {
        // --- STEP 1: Datadog SIEM Ingestion ---
        logSystem(`--- 침해 경보 감지: ${alert.title} ---`);
        const ddNode = document.getElementById('node-datadog');
        ddNode.classList.add('alerting');
        document.getElementById('datadog-badge').textContent = "ALERT DETECTED";
        
        logSystem(`수신된 Datadog Webhook 원본 데이터:\n${JSON.stringify({
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
        showSpeech('collector', "경보 데이터 감지. 원본 JSON 파싱 및 정규화 작업 중...");
        logCollector(`경보 데이터 수집 완료: [${alert.title}]`);
        logCollector(`필터링 및 로그 정적 스키마 변환 완료.`);
        
        await delay(1800);
        collectorNode.classList.remove('working');
        collectorNode.classList.add('success');
        document.getElementById('collector-status').textContent = "IDLE";
        removeLaser('flow-path-1');

        // --- STEP 3: T1 Analyst Ingests ---
        drawLaser('node-collector', 'node-analyst', 'flow-path-1', 'to-analyst');
        const analystNode = document.getElementById('node-analyst');
        analystNode.classList.add('working');
        document.getElementById('analyst-status').textContent = "INITIAL TRIAGE";
        showSpeech('analyst', "알림 분석 개시. 정확한 컨텍스트 파악을 위해 Datadog Agent에 연관 로그 쿼리를 요청합니다.");
        logAnalyst(`경보 초기 우선순위 평가 진행 중: ${alert.title}`);
        
        await delay(2000);
        removeLaser('flow-path-1');

        // --- STEP 4: T1 Analyst ➡️ Datadog Agent (Query Logs) ---
        drawLaser('node-analyst', 'node-dd-agent', 'flow-path-1', 'to-dd-agent');
        const ddAgentNode = document.getElementById('node-dd-agent');
        ddAgentNode.classList.add('working');
        document.getElementById('dd-agent-status').textContent = "LOG QUERYING";
        showSpeech('dd-agent', `보안 관제 데이터베이스에서 IoC [${alert.ioc}] 에 대한 과거 이력/연관 텔레메트리 조회 중...`);
        logDDAgent(`로그 조회 쿼리 실행: "${alert.queryText}"`);
        
        await delay(2200);
        logDDAgent(`쿼리 완료. 결과 수집: ${alert.queryResult}`);
        ddAgentNode.classList.remove('working');
        ddAgentNode.classList.add('success');
        document.getElementById('dd-agent-status').textContent = "IDLE";
        removeLaser('flow-path-1');

        // --- STEP 5: Datadog Agent ➡️ T1 Analyst (Return Query Results) ---
        drawLaser('node-dd-agent', 'node-analyst', 'flow-path-1', 'to-analyst');
        analystNode.classList.add('working');
        document.getElementById('analyst-status').textContent = "CORRELATING";
        showSpeech('analyst', "연관 로그 확인 완료. 위협 강도를 판정하기 위해 외부 Threat Intel 검토를 수행합니다.");
        logAnalyst(`조회된 이력 및 연관 텔레메트리 정보 분석: "${alert.queryResult}"`);
        
        await delay(2000);
        removeLaser('flow-path-1');

        // Escalation Check Branch (Malware Beacon Scenario)
        let activeAnalystNode = 'node-analyst';
        let activeAnalystStatus = 'analyst-status';
        let isEscalated = false;

        if (alert.escalationReason) {
            isEscalated = true;
            logAnalyst(`[에스컬레이션 감지] ${alert.escalationReason}`);
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
            logTier2(`에스컬레이션된 침해 사고 분석 시작. 사유: ${alert.escalationReason}`);
            
            await delay(2500);
            logTier2(alert.t2AnalysisLog);
            removeLaser('flow-path-2');
            
            activeAnalystNode = 'node-tier2-analyst';
            activeAnalystStatus = 'tier2-analyst-status';
        }

        // --- STEP 6: TI Expert Query (T1 또는 T2 ➡️ TI) ---
        // 에스컬레이션 여부에 따라 빔 출발지를 정적으로 분기하여 가독성 개선
        drawLaser(activeAnalystNode, 'node-ti', 'flow-path-1', isEscalated ? 'to-tier2' : 'to-analyst');
        const tiNode = document.getElementById('node-ti');
        tiNode.classList.add('working');
        document.getElementById('ti-status').textContent = "QUERYING";
        showSpeech('ti', `인텔리전스 데이터베이스에서 "${alert.ioc}" 평판 정보 크로스체크 중...`);
        logTI(`Threat Intel 평판 정보 조회 요청: ${alert.ioc}`);
        
        await delay(2300);
        logTI(`평판 조회 완료: ${alert.tiDescription}`);
        tiNode.classList.remove('working');
        tiNode.classList.add('success');
        document.getElementById('ti-status').textContent = "IDLE";
        removeLaser('flow-path-1');

        // --- STEP 7: TI Expert ➡️ Analyst (TI ➡️ T1 또는 T2) ---
        // 복귀하는 빔의 색깔과 도착지도 T1/T2 분기를 완벽히 반영
        drawLaser('node-ti', activeAnalystNode, 'flow-path-1', isEscalated ? 'to-tier2' : 'to-analyst');
        document.getElementById(activeAnalystStatus).textContent = "DECISION MAKING";
        if (isEscalated) {
            logTier2(`TI 위협 정보 매칭 성공: ${alert.tiDescription}. 차단 정책 도출 중.`);
            showSpeech('tier2-analyst', "TI 검증 완료. 침해사고 대응 지침에 따라 차단안을 작성하고 Validator 승인을 요청합니다.");
        } else {
            logAnalyst(`TI 위협 정보 매칭 성공: ${alert.tiDescription}. 차단 정책 도출 중.`);
            showSpeech('analyst', "TI 검증 완료. 차단 대응조치를 생성하여 Validator Agent에게 영향도 검토를 요청합니다.");
        }
        
        await delay(2000);
        removeLaser('flow-path-1');

        // --- STEP 8: Analyst ➡️ Validator Agent (Audit & Logic Check) ---
        drawLaser(activeAnalystNode, 'node-validator', 'flow-path-1', 'to-validator');
        const validatorNode = document.getElementById('node-validator');
        validatorNode.classList.add('working');
        document.getElementById('validator-status').textContent = "AUDITING";
        showSpeech('validator', `최종 제안된 조치의 비즈니스 영향도 평가 중: [${alert.validatorRule}]`);
        logValidator(`최종 검증 감사 착수... 차단 대상: [${alert.ioc}]`);
        logValidator(`영향성 및 FP 검토 결과: ${alert.validatorVerdict}`);
        
        await delay(2600);
        
        let decisionApproved = true;
        if (type === 'bruteforce') {
            decisionApproved = false; // Google DNS block should be REJECTED!
        }
        
        removeLaser('flow-path-1');

        // --- STEP 9: Validator Agent Verdict ➡️ Analyst (Approve/Reject) ---
        // ★ 버그 수정: 검증 결과 피드백 빔이 T1 또는 T2 분석가에게 분기되어 돌아가도록 수정
        if (decisionApproved) {
            approvedBlocksCount++;
            document.getElementById('metric-blocks').textContent = approvedBlocksCount;
            validatorNode.classList.remove('working');
            validatorNode.classList.add('success');
            document.getElementById('validator-status').textContent = "APPROVED";
            showSpeech('validator', "검증 완료: 서비스 영향도 검토 결과 안전함. 차단 조치안 최종 승인!");
            logSuccess(`분석 검증 승인. 정책 실행 엔진에 대응 지시를 하달합니다.`);
            
            // 검증 결과 피드백을 활성 분석가에게 전달
            drawLaser('node-validator', activeAnalystNode, 'flow-path-1', isEscalated ? 'to-tier2' : 'to-analyst');
            await delay(1200);
            removeLaser('flow-path-1');
            
            postToSlack(alert, 'APPROVED', isEscalated);
        } else {
            rejectedProposalsCount++;
            document.getElementById('metric-rejects').textContent = rejectedProposalsCount;
            validatorNode.classList.remove('working');
            validatorNode.classList.add('danger-state');
            document.getElementById('validator-status').textContent = "REJECTED";
            showSpeech('validator', "🚨 검증 거부! 중요 공용 IP 차단은 전사 네트워크 장애를 초래합니다! 즉각 조치 반려.", 3500);
            logFailure(`분석 검증 반려. 중요 공용 자산(DNS)에 대한 위험 차단 차단.`);
            
            // 검증 결과 반려 피드백을 활성 분석가에게 전달
            drawLaser('node-validator', activeAnalystNode, 'flow-path-1', isEscalated ? 'to-tier2' : 'to-analyst');
            await delay(1200);
            removeLaser('flow-path-1');
            
            postToSlack(alert, 'REJECTED', isEscalated);
        }

        await delay(2500);

        // Reset
        logSystem(`--- 침해사고 조사 및 조치 프로세스 완료 ---`);
        resetSimulationState();

    } catch (e) {
        logTerminal(`[에러] 시뮬레이션 실행 중 실패: ${e.message}`, 'error-msg');
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
                <span>🔴 [차단 제안 승인 완료] ${alert.title}</span>
                <span style="color:#6b7280; font-weight:normal; font-size:10px; margin-left:auto;">${timeStr}</span>
            </div>
            <div class="slack-msg-body">
                <strong>판정 결과:</strong> True Positive (실제 침해) | Validator 검증 완료 ✅<br>
                <strong>차단 대상 IoC:</strong> <code>${alert.ioc}</code> (${alert.iocType})<br>
                <strong>조치 결과:</strong> ${alert.slackMsg}<br>
                <strong>영향도 보고:</strong> ${alert.validatorVerdict}
            </div>
            <div class="slack-msg-meta">
                분석 에이전트: ${isEscalated ? 'Tier 2 AI (상위 분석가)' : 'Tier 1 AI (초기 분석가)'} | 감사 에이전트: Validator Agent v1.0
            </div>
        `;
    } else {
        card.className = 'slack-msg-card rejected';
        card.innerHTML = `
            <div class="slack-msg-title" style="color:var(--color-warning);">
                <span>⚠️ [차단 조치 즉각 반려] ${alert.title}</span>
                <span style="color:#6b7280; font-weight:normal; font-size:10px; margin-left:auto;">${timeStr}</span>
            </div>
            <div class="slack-msg-body">
                <strong style="color:var(--color-warning);">판정 결과:</strong> 오판(False Positive) / 중요 공유 자산 차단 감지 ❌<br>
                <strong>요청된 IoC:</strong> <code>${alert.ioc}</code> (${alert.iocType})<br>
                <strong>반려 사유(Validator):</strong> <span style="color:#fca5a5;">${alert.validatorVerdict}</span><br>
                <strong>대응 조치:</strong> 자동화 차단 조치가 안전하게 취소되었습니다. 관제실 담당 엔지니어 연동 티켓 발송.
            </div>
            <div class="slack-msg-meta">
                분석 에이전트: Tier 1 AI | 감사 에이전트: Validator Agent v1.0 (중요 장애 방지용 검증)
            </div>
        `;
    }
    
    slackFeed.insertBefore(card, slackFeed.firstChild);
    slackFeed.scrollTop = 0;
}

window.addEventListener('DOMContentLoaded', () => {
    updateClock();
    logSystem("모든 CERT 에이전트의 관제 분석 서브루틴이 로드되었습니다.");
});
