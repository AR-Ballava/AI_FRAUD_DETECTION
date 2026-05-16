from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_service_url: AnyHttpUrl = Field("http://model:8001", alias="MODEL_SERVICE_URL")
    redis_url: str | None = Field(None, alias="REDIS_URL")
    rate_limit: str = Field("60/minute", alias="RATE_LIMIT")
    scrape_timeout: float = Field(10.0, alias="SCRAPE_TIMEOUT")
    allowed_origins: str = Field("*", alias="ALLOWED_ORIGINS")
    fraud_osint_threshold: float = Field(10.0, alias="FRAUD_OSINT_THRESHOLD")
    max_text_chars: int = Field(120_000, alias="MAX_TEXT_CHARS")
    max_file_size: int = Field(10 * 1024 * 1024, alias="MAX_FILE_SIZE")
    analytics_path: str = Field("app/data/analytics.json", alias="ANALYTICS_PATH")

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def origins(self) -> list[str]:
        if self.allowed_origins.strip() == "*":
            return ["*"]
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

