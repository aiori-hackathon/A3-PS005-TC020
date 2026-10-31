"""Vercel ASGI entrypoint for the BGP Sentinel API."""

from src.api.main import app

__all__ = ["app"]
