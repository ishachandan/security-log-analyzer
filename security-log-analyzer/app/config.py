"""
Centralized Configuration
All environment variables and settings in one place
"""
import os

# Flask Configuration
FLASK_SECRET = os.getenv("FLASK_SECRET", "change-me-in-production")
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"

# Authentication Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", 24))

# Alerting Configuration - Webhook
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", None)
WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", 5))

# Alerting Configuration - Email
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", None)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", None)
SMTP_PASS = os.getenv("SMTP_PASS", None)

# Database Configuration
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/users.db")

# Ollama Configuration
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "localhost")
OLLAMA_PORT = int(os.getenv("OLLAMA_PORT", 11434))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", 120))

# ChromaDB Configuration
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000))
CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "data/chromadb")
