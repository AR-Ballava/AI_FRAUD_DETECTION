from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_path: str = Field("models/job_fraud_model.pt", alias="MODEL_PATH")
    max_file_size: int = Field(10 * 1024 * 1024, alias="MAX_FILE_SIZE")
    inference_timeout: float = Field(20.0, alias="INFERENCE_TIMEOUT")
    max_text_chars: int = Field(120_000, alias="MAX_TEXT_CHARS")

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()

