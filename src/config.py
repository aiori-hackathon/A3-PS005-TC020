"""Application configuration loaded from environment variables."""

from dataclasses import dataclass
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional during minimal imports
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_path: str = "data/bgp_sentinel.db"
    database_url: str | None = None
    inventory_path: str | None = None
    roa_path: str | None = None
    cors_origins: str = "*"
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_path=os.getenv("BGP_DATABASE_PATH", os.getenv("DATABASE_PATH", cls.database_path)),
            database_url=os.getenv("DATABASE_URL"),
            inventory_path=os.getenv("BGP_INVENTORY_PATH"),
            roa_path=os.getenv("BGP_ROA_PATH"),
            cors_origins=os.getenv("BGP_CORS_ORIGINS", cls.cors_origins),
            api_host=os.getenv("BGP_API_HOST", cls.api_host),
            api_port=int(os.getenv("BGP_API_PORT", str(cls.api_port))),
        )


settings = Settings.from_env()


def ensure_database_parent(path: str) -> None:
    """Create the parent directory for a file-backed SQLite database."""
    if path != ":memory:":
        Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
