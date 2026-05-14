"""
config.py — Centralized settings using pydantic-settings.

All secrets come from environment variables / .env file.
Never hard-code credentials here.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # OpenAI
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"          # cost-efficient default

    # Wazuh
    WAZUH_BASE_URL: str = "https://your-wazuh-host:55000"
    WAZUH_USER: str = "wazuh-wui"
    WAZUH_PASSWORD: str = ""
    WAZUH_VERIFY_SSL: bool = False              # set True in prod with valid cert

    # Supabase
    SUPABASE_URL: str = ""
    SUPABASE_SERVICE_KEY: str = ""             # service role key (backend only)

    # App
    FRONTEND_URL: str = "https://your-app.vercel.app"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "change-me-in-production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
