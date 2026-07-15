# CERT AI Agent Virtual Office Simulator (v2.0)

멀티 에이전트 협업 기반의 **실시간 침해사고 대응 및 의사결정 시뮬레이터**입니다.  
보안 관제 센터(SOC) 컨셉의 모던 다크 테마 대시보드 내에서, 여러 특화 AI 에이전트들이 위협 경보 분석, 연관 로그 조회, 에스컬레이션, 그리고 최종 조치의 안전성 검증(반려/승인)을 수행하는 흐름을 시각적으로 보여줍니다.

---

## 🏢 AI 에이전트 구성 (6개 에이전트)

1. **Collector Agent (Normalizer) 🤖**
   - Datadog SIEM에서 유입되는 원본 Alert Webhook 페이로드를 정규화하고 필터링합니다.
2. **Datadog Agent (Query Assistant) 🐕**
   - 분석가 에이전트의 요청을 받아 과거 위협 이력 및 자산(Asset) 텔레메트리 연관 검색을 수행합니다.
3. **Tier 1 Analyst AI (Triage) 🧠**
   - 최초 분석을 진행하며 로그 유입 패턴 분석 및 IoC 침해지표(IP, Domain)를 추출합니다.
4. **Tier 2 Analyst AI (Deep Analyst) 🕵️‍♂️**
   - Tier 1에서 판단이 보류된 고위험/지능형 위협을 인계받아 정적 시그니처 분석 등 정밀 분석을 수행합니다.
5. **TI Expert Agent (Threat Intelligence) 🔍**
   - 외부 블랙리스트 DB 및 평판 정보(VirusTotal 등)를 조회하여 위협 등급을 피드백합니다.
6. **Validator Agent (Impact Auditor) ⚖️**
   - 비판적 사고에 의거하여 제안된 조치가 내부 비즈니스 가동성에 미칠 부작용을 사전에 검증하고 **승인(Approve) 또는 반려(Reject)**를 결정합니다.

---

## 🎬 3대 대응 시나리오

### 1. DDoS Attack (Tier 1 대응 ➡️ 승인 ✅)
* **상황**: 외부 특정 IP에서 유입되는 대규모 유입 트래픽 감지.
* **진행**: Collector ➡️ Tier 1 Analyst ➡️ Datadog Agent(과거 2회 공격 이력 확인) ➡️ TI Expert(Mirai Botnet C2 판정) ➡️ Validator Agent (외부 IP이므로 서비스 영향 없음 판정, **최종 승인**) ➡️ Slack 자동 차단 보고서 발행.

### 2. Brute Force (공용 IP 오판 ➡️ 반려 ❌)
* **상황**: SSH 로그인 실패 로그 다수 발생.
* **진행**: Collector ➡️ Tier 1 Analyst (출발지 IP `8.8.8.8` 차단안 제안) ➡️ Datadog Agent(Google Public DNS 자산 식별) ➡️ TI Expert (안전성 검증) ➡️ Validator Agent (**비판적 거부**: *공용 DNS 차단 시 전사 인터넷 다운 위험 감지* ➡️ **최종 반려**) ➡️ Slack 조치 반려 보고서 발행.

### 3. Malware Beacon (Tier 2 에스컬레이션 ➡️ 승인 ✅)
* **상황**: 내부 PC에서 suspicious-beacon.ru 도메인 쿼리 발생.
* **진행**: Collector ➡️ Tier 1 Analyst (추가 텔레메트리 쿼리) ➡️ Tier 1 Analyst (난독화 패턴 확인, **Tier 2 에스컬레이션**) ➡️ Tier 2 Analyst (정밀 분석) ➡️ TI Expert(Hermit Ransomware 연동 확인) ➡️ Validator Agent (HR 단말 격리 영향 미미 판정 ➡️ **최종 승인**) ➡️ Slack 단말 격리 보고서 발행.

---

## 🚀 로컬 실행 방법

본 프로젝트는 백엔드 없이 정적 HTML/CSS/JS로 동작하여 가볍게 데모를 시연할 수 있습니다.

1. **저장소 복제 및 폴더 이동**
   ```bash
   git clone https://github.com/pwnbit/cert-ai-dashboard.git
   cd cert-ai-dashboard
   ```

2. **로컬 웹 서버 가동**
   * Python 사용 시:
     ```bash
     python -m http.server 8000
     ```
   * Node.js 사용 시:
     ```bash
     npx serve -l 8000
     ```

3. **데모 확인**
   * 브라우저에서 **[http://localhost:8000](http://localhost:8000)**에 접속하여 원하는 시나리오 버튼을 클릭하여 시뮬레이션을 재생합니다.

---

## 📂 파일 구조

* `index.html`: SOC 관제실 및 Slack 피드, 제어판 마크업.
* `styles.css`: Glassmorphism 효과, 에이전트 둥둥 뜨는(Float) 효과 및 SVG 레이저 빔 애니메이션 스타일시트.
* `app.js`: 시간 조절(1x, 2x, 4x) 및 각 에이전트 간 비동기 소통 파이프라인 시뮬레이션 엔진.
* `walkthrough.md`: 상세 설계 사양 및 에이전트 시퀀스 단계 기술 보고서.
