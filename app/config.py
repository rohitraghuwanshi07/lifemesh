from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "sqlite:///./lifemesh.db"
    secret_key: str = "dev-insecure-change-me"
    token_key: str = ""  # Fernet key; required in production
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/integrations/google/callback"
    ms_client_id: str = ""
    ms_client_secret: str = ""
    ms_redirect_uri: str = "http://localhost:8000/integrations/microsoft/callback"
    webhook_secret: str = ""
    public_url: str = "http://localhost:8000"
    gmail_pubsub_topic: str = ""
    otel_endpoint: str = ""
    redis_url: str = "redis://localhost:6379/0"
    model_config = {"env_file": ".env", "extra": "ignore"}

settings = Settings()
