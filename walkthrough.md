# CERT AI Agent Virtual Office Simulator (v2.1) 구현 완료 보고서

본 보고서는 **CERT(Cyber Incident Response Team) Tier 1 & Tier 2 AI 에이전트 협업 관제 모델**의 웹 시뮬레이터 구현 세부 사양 및 최종 패치 내역을 기술합니다.

---

## 1. 확장된 파일 및 에이전트 구성 (v2.1 기준)

데모 코드는 default 프로젝트 디렉토리 내의 [cert-ai-demo](file:///C:/Users/ic211/.gemini/antigravity/scratch/cert-ai-demo) 서브디렉토리에 위치해 있습니다.

### 🏢 에이전트 목록 (총 6개 에이전트)
1. **Collector Agent 🤖**: SIEM 알림 수집 및 파싱/정규화 수행.
2. **Datadog Agent 🐕**: 분석가의 요청에 따라 데이터베이스에서 연관 로그 검색 및 과거 이력 조회. (오렌지 톤)
3. **Tier 1 Analyst AI 🧠**: 최초 수집된 알림의 위협 분류 및 기본 분석 수행. (퍼플 톤)
4. **Tier 2 Analyst AI 🕵️‍♂️**: Tier 1에서 판단이 불가한 복잡한 위협의 정밀 분석 및 정적 시그니처 분석 인계(에스컬레이션). (핑크 톤)
5. **TI Expert Agent 🔍**: 외부 블랙리스트 DB 및 위협 인텔리전스 조회. (민트 톤)
6. **Validator Agent ⚖️**: 최종 차단 조치 전 비즈니스 영향도 평가 및 오판(False Positive) 방지 필터링. (골드 톤)

---

## 2. 패치 및 업데이트 내역 (v2.1)

### ① 에스컬레이션 피드백 액션 빔 수정
- **문제점**: Tier 2 에스컬레이션 시나리오(Malware Beacon) 진행 시, TI Expert의 응답 및 Validator Agent의 최종 승인 결과가 발생했을 때 빔이 Tier 2가 아닌 Tier 1 분석가(`node-analyst`)로 복귀하여 T2의 활동이 끊겨 보였던 현상.
- **해결책**: `app.js` 내의 빔 타겟(Target ID)을 정적 코드에서 현재 활성화된 분석가 노드 변수(`activeAnalystNode`)로 동적 매칭시켰습니다.
  - TI ➡️ T2 Analyst 피드백 시 핑크색 빔 (`to-tier2`) 표현.
  - Validator ➡️ T2 Analyst 승인 하달 시 핑크색 빔 (`to-tier2`) 표현.

### ② 관제 대화 및 터미널 로그 전면 한글화
- 우측 **Agent Dialogue & Activity Logs(관제 터미널)**의 데이터 쿼리 로그, 수집/분석 과정 로그를 모두 한글로 표기했습니다.
- 에이전트 아바타 위에 뜨는 **말풍선(Speech Bubble)**을 직관적인 한국어 관제 메시지로 수정했습니다.
- 하단 **Slack 라이브 피드**에 노출되는 최종 조치 결과 및 영향성 판단 리포트의 타이틀, 내용, 메타 정보를 한글화하여 시인성을 높였습니다.

### ③ 4K 고해상도 모니터 반응형 배치 최적화
- 기존 절대 좌표(`px`) 배치로 인해 고해상도 대형 디스플레이 환경에서 에이전트 노드가 지나치게 상하로 뭉쳐있거나 공백이 비대해지던 현상을 개선했습니다.
- CSS의 비율(`%`) 단위를 이용하여 해상도가 늘어나더라도 `25%`, `50%`, `75%` 축에 맞춰 고르게 분산 배치되도록 레이아웃 정합성을 맞추었습니다.

---

## 3. 3대 주요 시나리오 및 통신망 흐름

가상 오피스 내에서 발생할 수 있는 시나리오별 통신 흐름은 다음과 같습니다.

### Scenario 1. DDoS Attack (Tier 1 대응 ➡️ Validator 승인)
* **목적**: 전형적인 외부 위협 탐지 시 순차적 탐지 및 자동 차단 흐름 검증.
* **통신망 흐름**:
  1. Datadog SIEM Alert ➡️ Collector ➡️ Tier 1 Analyst
  2. Tier 1 Analyst ➡️ **Datadog Agent (과거 차단 이력 2회 조회 성공)** ➡️ Tier 1 Analyst
  3. Tier 1 Analyst ➡️ TI Agent (IP 평판 조회: Mirai Botnet C2 확인) ➡️ Tier 1 Analyst
  4. Tier 1 Analyst ➡️ **Validator Agent (검증 요청)**
  5. Validator Agent (영향도 평가: 내부 주요 자산과 무관하며 서비스 영향 없음 판정 ➡️ **승인**)
  6. Validator ➡️ Slack 피드에 자동 차단 조치 성공 보고서 발송.

### Scenario 2. Brute Force (공용 IP 오판 ➡️ Validator 반려 ❌)
* **목적**: 시스템 가동성에 위협이 될 수 있는 오판 차단(False Positive)을 Validator가 비판적 사고로 감지 및 방어하는 로직 검증.
* **통신망 흐름**:
  1. Datadog SIEM Alert (SSH 실패 감지, 출발지 IP `8.8.8.8`) ➡️ Collector ➡️ Tier 1 Analyst
  2. Tier 1 Analyst ➡️ **Datadog Agent (Asset 데이터베이스 조회 결과 Google Public DNS 식별)** ➡️ Tier 1 Analyst
  3. Tier 1 Analyst ➡️ TI Agent (DNS 서버 평판 조회: 신뢰도 안전) ➡️ Tier 1 Analyst
  4. Tier 1 Analyst (판단 오류로 IP `8.8.8.8` 방화벽 영구 차단 조치안 제안) ➡️ **Validator Agent (검증 요청)**
  5. Validator Agent (영향도 평가: **차단 대상이 구글 공용 DNS 자산임을 탐지. 차단 시 사내 전체 인터넷 장애 발생 위험 경고 ➡️ 반려(Reject)**)
  6. Validator ➡️ Slack 피드에 자동 차단 반려 보고서 및 분석가 경고 카드 발송 (시스템 장애 예방 성공).

### Scenario 3. Malware Beacon (Tier 2 에스컬레이션 ➡️ 승인 ✅)
* **목적**: 심층 조사가 요구되는 난독화 위협에 대한 하위 에이전트 간 에스컬레이션 흐름 검증.
* **통신망 흐름**:
  1. Datadog SIEM Alert (Suspicious Domain Query) ➡️ Collector ➡️ Tier 1 Analyst
  2. Tier 1 Analyst ➡️ **Datadog Agent (HR 단말 추가 텔레메트리 쿼리)** ➡️ Tier 1 Analyst
  3. Tier 1 Analyst (난독화 패턴 및 프로세스 메모리 주입 징후 발견 ➡️ **Tier 2 Analyst로 Escalation**)
  4. **Tier 2 Analyst (정밀 분석 개시)** ➡️ TI Agent (Hermit Ransomware 연동 확인) ➡️ Tier 2 Analyst
  5. Tier 2 Analyst (감염 단말 격리 및 도메인 싱크홀링 조치안 제안) ➡️ **Validator Agent (검증 요청)**
  6. Validator Agent (영향도 평가: 격리 대상이 비중요 HR PC이며 도메인 차단 무해 판정 ➡️ **승인**)
  7. Validator ➡️ Slack 피드에 격리 및 싱크홀링 완료 보고서 발송.
