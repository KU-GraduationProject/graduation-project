# Leafy AIOps 아키텍처

[편집 가능한 draw.io 파일](leafy-aiops.drawio)과 [확대·검색 가능한 HTML 미리보기](leafy-aiops.html)이다. HTML은 단일 파일이며 별도 서버나 외부 리소스 없이 열린다.

| 페이지 | 내용 | PNG |
|---|---|---|
| 01 전체 구조 | Leafy, 수집기, 저장소, Alertmanager, Pipeline, Ollama, Remediation의 핵심 연결이다. | [전체 구조](leafy-aiops.png) |
| 02 로그와 네트워크 | 앱 로그 경로와 Zeek → Enricher → Fluentd → Loki 경로이다. | [수집 흐름](logs-network.png) |
| 03 분석과 대응 | Alert 수신, 컨텍스트 상관, LLM 분석, 결과 기록과 대응 분기이다. | [분석·대응](rca-response.png) |

Compose와 현재 코드에서 확인한 **선언 및 구현 구조**이다. Docker를 조회하거나 실행한 결과가 아니며, Remediation의 중지 표시는 사용자 제공 상태이다. 빨간 점선은 현재 실행되지 않는 대응 경로이다. 요약 상자와 Pipeline 처리 단계는 추가 컨테이너가 아니다.

주요 근거는 `docker-compose.yml`, `docker-compose.gpu.yml`, `leafy/fluentd/fluent.conf`, `monitoring/` 설정과 `aiops/pipeline/`, `aiops/remediation/` 코드이다. 각 구성 요소의 파일·행 근거와 네트워크·포트 정보는 [Diagram IR](leafy-aiops.ir.json) 및 draw.io 셀 메타데이터에 저장된다. Secret과 환경변수 값은 저장하지 않는다.

PNG는 diagrams.net의 실제 렌더러를 headless 브라우저로 확인한 미리보기이다. HTML과 개별 SVG는 같은 좌표·경유점에서 생성하는 오프라인 미리보기이며 draw.io 데스크톱의 네이티브 내보내기는 아니다. HTML에서는 페이지 전환, 확대·축소, 드래그 이동, 노드 검색과 텍스트 설명을 사용할 수 있다.

저장소 루트에서 다음 명령으로 `.drawio`, 모델, HTML과 SVG를 다시 생성한다. Python, PyYAML, 설치된 `drawio-skill`을 사용하며 Docker나 프로젝트 서비스에는 접근하지 않는다. 수동으로 다이어그램을 편집했다면 생성 명령이 덮어쓰므로 원본을 별도로 보존한다. PNG는 이 명령으로 갱신되지 않는다.

```powershell
python -B docs/architecture/generate_architecture.py
```
