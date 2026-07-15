# CERT AI Agent Virtual Office Simulator (v2.0) 구현 완료 보고서

Tier 1 AI 분석가의 탐색 범위 확장을 위한 **Datadog Agent(로그 및 이력 조회)**, 정밀 분석을 위한 **Tier 2 AI 분석가(에스컬레이션)**, 최종 의사결정의 안전을 담보하는 **Validator Agent(비판적 승인/반려 게이트키퍼)**를 가상 오피스에 완전히 통합하고 모든 연동 및 시나리오 동작 검증을 완료하였습니다.

---

## 1. 확장된 파일 및 에이전트 구성

데모 코드는 default 프로젝트 디렉토리 내의 [cert-ai-demo](file:///C:/Users/ic211/.gemini/antigravity/scratch/cert-ai-demo) 서브디렉토리에 위치해 있습니다.

### 🏢 추가 및 수정된 에이전트 목록 (총 6개 에이전트)
1. **Collector Agent 🤖**: SIEM 알림 수집 및 정규화.
2. **Datadog Agent 🐕**: 분석가의 요청에 따라 데이터베이스에서 연관 로그 검색 및 과거 차단 이력 조회. (오렌지 톤)
3. **Tier 1 Analyst AI 🧠**: 최초 수집된 알림의 위협 분류 및 기본 분석 수행. (퍼플 톤)
4. **Tier 2 Analyst AI 🕵️‍♂️**: Tier 1에서 판단이 불가한 복잡한 위협의 정밀 분석 및 정적 시그니처 분석 인계(에스컬레이션). (핑크 톤)
5. **TI Expert Agent 🔍**: 외부 블랙리스트 DB 및 위협 인텔리전스 조회. (민트 톤)
6. **Validator Agent ⚖️**: 최종 차단 조치 전 비즈니스 영향도 평가 및 오판(False Positive) 방지 필터링. (골드 톤)

---

## 2. 3대 주요 시나리오 및 통신망 흐름

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

### Scenario 3. Malware Beacon (Tier 2 Escalation ➡️ Validator 승인)
* **목적**: 심층 조사가 요구되는 난독화 위협에 대한 하위 에이전트 간 에스컬레이션 흐름 검증.
* **통신망 흐름**:
  1. Datadog SIEM Alert (Suspicious Domain Query) ➡️ Collector ➡️ Tier 1 Analyst
  2. Tier 1 Analyst ➡️ **Datadog Agent (HR 단말 추가 텔레메트리 쿼리)** ➡️ Tier 1 Analyst
  3. Tier 1 Analyst (난독화 패턴 및 프로세스 메모리 주입 징후 발견 ➡️ **Tier 2 Analyst로 Escalation**)
  4. **Tier 2 Analyst (정밀 분석 개시)** ➡️ TI Agent (Hermit Ransomware 연동 확인) ➡️ Tier 2 Analyst
  5. Tier 2 Analyst (감염 단말 격리 및 도메인 싱크홀링 조치안 제안) ➡️ **Validator Agent (검증 요청)**
  6. Validator Agent (영향도 평가: 격리 대상이 비중요 HR PC이며 도메인 차단 무해 판정 ➡️ **승인**)
  7. Validator ➡️ Slack 피드에 격리 및 싱크홀링 완료 보고서 발송.

---

## 3. 최종 검증 내역

- **시나리오 로직**: Brute Force 및 Malware 시나리오를 구동하여, **Datadog Agent를 통한 로그 조회 ➡️ Tier 2로의 에스컬레이션 ➡️ Validator Agent의 비판적 영향도 평가 및 반려(Reject)** 의 전체 프로세스가 막힘없이 자연스러운 지연을 거쳐 정확한 타임스탬프와 함께 수행됨을 확인했습니다.
- **슬랙 알림 시각화**: 차단 승인 시 녹색 테두리의 `[AUTOMATED BLOCK PUSHED]`가 발행되며, 조치 반려 시 회색/경고 테두리의 `[MITIGATION BLOCK BLOCKED]` 카드가 반려 사유와 함께 실시간으로 발행됨을 검증했습니다.
- **메트릭 정합성**: 각 이벤트의 완료 시점에 맞추어 Ingested, Approved Blocks, Rejected Proposals 카운터가 유기적으로 갱신됨을 확인했습니다.
