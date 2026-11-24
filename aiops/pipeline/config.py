import os


class Settings:
    prometheus_url: str = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
    loki_url: str = os.getenv("LOKI_URL", "http://loki:3100")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://ollama:11434")
    remediation_url: str = os.getenv("REMEDIATION_URL", "http://remediation:8001")
    llm_model: str = os.getenv("LLM_MODEL", "llama3.1:8b")  # ← 3b → 8b
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "180"))  # 120 → 180
    # Ollama 호출 options. 재현 가능한 측정을 위해 서버 기본값에 맡기지 않고 명시한다.
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.3"))
    llm_num_ctx: int = int(os.getenv("LLM_NUM_CTX", "4096"))
    llm_num_predict: int = int(os.getenv("LLM_NUM_PREDICT", "400"))
    # 비우면 호출에 seed 를 넣지 않는다 (Ollama 가 매번 무작위 seed 사용).
    llm_seed: int | None = int(os.getenv("LLM_SEED")) if os.getenv("LLM_SEED") else None
    # RCA LLM 공급자: gemini(기본, GPU·Ollama 불필요) | ollama(기존 로컬 경로)
    llm_provider: str = (os.getenv("LLM_PROVIDER") or "gemini").strip().lower()
    # 키는 환경변수로만 받는다. 로그·예외 메시지에 넣지 않는다.
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL") or "gemini-3.5-flash-lite"
    gemini_timeout: float = float(os.getenv("GEMINI_TIMEOUT", "30"))
    gemini_max_output_tokens: int = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "1024"))
    # 429·일시적 5xx 에만 쓰는 추가 시도 횟수 (총 호출 ≤ 1 + 이 값). 지연은 base × 2^n 초
    gemini_max_retries: int = int(os.getenv("GEMINI_MAX_RETRIES", "2"))
    gemini_retry_base_delay: float = float(os.getenv("GEMINI_RETRY_BASE_DELAY", "2"))
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
    # RCA 알림은 /notify 로만 보낸다. 운영 전환은 명시 opt-in 이며 /action 을 열지 않는다.
    remediation_notification_enabled: bool = os.getenv("REMEDIATION_NOTIFICATION_ENABLED", "false").lower() == "true"
    # Propose manual approval records only. The new operation is rejected by older Controllers.
    remediation_approval_enabled: bool = os.getenv("REMEDIATION_APPROVAL_ENABLED", "false").lower() == "true"
    remediation_proposal_min_confidence: float = float(os.getenv("REMEDIATION_PROPOSAL_MIN_CONFIDENCE", "0.8"))
    # 노션: medium 조치 자동 실행 + 사후 알림. 켜면 RCA 제안을 propose_rca_action 으로 보내고,
    # Controller 도 같은 플래그가 켜져 있어야 자동 실행한다. 기본 false = 모든 제안이 수동 승인.
    remediation_auto_execute_enabled: bool = os.getenv("REMEDIATION_AUTO_EXECUTE_ENABLED", "false").lower() == "true"
    # Remediation 서명 공유키. 미설정이면 알림 전달을 생략한다 (fail closed).
    remediation_api_key: str = os.getenv("REMEDIATION_API_KEY", "")
    # 원격 대상 이름 -> canonical service. 형식은 correlation.parse_target_map 참고. 비우면 Docker metadata만 쓴다.
    target_service_map: str = os.getenv("TARGET_SERVICE_MAP", "")
    # 프롬프트 조립 방식. v2 = 룰 기준 조회 구간·증거 ID·섹션별 예산, legacy = 1학기 방식(전후 비교용).
    prompt_builder: str = os.getenv("PROMPT_BUILDER", "v2")
    observation_bindings: str = os.getenv("OBSERVATION_BINDINGS", "[]")
    # 경보별 입력 컨텍스트 저장 위치(평가 픽스처용). 비우면 저장하지 않는다. 예: /app/results/context
    context_capture_dir: str = os.getenv("CONTEXT_CAPTURE_DIR", "")
settings = Settings()

