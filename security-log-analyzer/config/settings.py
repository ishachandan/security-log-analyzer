"""
Configuration module for Security Log Analyzer
Centralized settings for all components
"""
import os
import secrets
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
CHROMA_DIR = DATA_DIR / "chromadb"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
CHROMA_DIR.mkdir(exist_ok=True)

# Flask Configuration
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"

# Authentication Configuration
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", 24))

# Embedding Model Configuration
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384

# ChromaDB Configuration
CHROMA_COLLECTION_PREFIX = "security_logs"
CHROMA_COLLECTIONS = {
    "auth": f"{CHROMA_COLLECTION_PREFIX}_auth",
    "http": f"{CHROMA_COLLECTION_PREFIX}_http",
    "system": f"{CHROMA_COLLECTION_PREFIX}_system",
    "custom": f"{CHROMA_COLLECTION_PREFIX}_custom"
}

# Ollama Configuration
OLLAMA_MODEL = "phi"
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_TIMEOUT = 120

# Query Configuration
TOP_K_RESULTS = 5
MAX_CONTEXT_LENGTH = 2000

# Chunking Configuration
CHUNK_SIZE = 500  # characters
CHUNK_OVERLAP = 50

# Log Processing
SUPPORTED_LOG_TYPES = ["syslog", "json", "csv", "apache", "nginx"]
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z"
]

# API Configuration
API_PREFIX = "/api"
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
