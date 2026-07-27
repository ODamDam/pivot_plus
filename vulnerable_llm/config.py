from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "vul-dolphin:latest"
    OLLAMA_TIMEOUT_SEC: float = 60.0

    DEFAULT_TEMPERATURE: float = 0.0
    DEFAULT_MAX_TOKENS: int = 512
    MAX_MAX_TOKENS: int = 2048

    LOG_DIR: str = "./data"
    ENABLE_HIGH_RISK_BLOCK: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()