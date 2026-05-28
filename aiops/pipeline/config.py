import os


class Settings:
    prometheus_url: str = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
    loki_url: str = os.getenv("LOKI_URL", "http://loki:3100")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://ollama:11434")
    remediation_url: str = os.getenv("REMEDIATION_URL", "http://remediation:8001")
    llm_model: str = os.getenv("LLM_MODEL", "llama3.1:8b")  # ← 3b → 8b
    llm_timeout: float = float(os.getenv("LLM_TIMEOUT", "120"))  # ← 추가
    slack_webhook_url: str = os.getenv("SLACK_WEBHOOK_URL", "")
settings = Settings()

