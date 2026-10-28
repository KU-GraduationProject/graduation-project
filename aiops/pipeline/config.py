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
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
    # Remediation /action 서명 공유키. 미설정이면 조치 전달을 생략한다 (fail closed).
    remediation_api_key: str = os.getenv("REMEDIATION_API_KEY", "")
    # 원격 대상 이름 -> canonical service. 형식은 correlation.parse_target_map 참고. 비우면 Docker metadata만 쓴다.
    target_service_map: str = os.getenv("TARGET_SERVICE_MAP", "")
settings = Settings()

