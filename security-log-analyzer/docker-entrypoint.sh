#!/bin/bash
# Docker Entrypoint Script
# Waits for dependencies and initializes the application

set -e

echo "=========================================="
echo "Security Log Analyzer - Starting"
echo "=========================================="

# Function to wait for a service
wait_for_service() {
    local service_name=$1
    local url=$2
    local max_attempts=$3
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        echo "   Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "❌ ERROR: $service_name failed to become ready after $max_attempts attempts"
    exit 1
}

# Wait for ChromaDB (max 30 seconds)
wait_for_service "ChromaDB" "http://chromadb:8000/api/v1/heartbeat" 15

# Wait for Ollama (max 60 seconds)
wait_for_service "Ollama" "http://ollama:11434/api/tags" 30

# Pull Phi model if not already present
echo "🔄 Checking Ollama model..."
if curl -sf "http://ollama:11434/api/tags" | grep -q "phi"; then
    echo "✅ Phi model already available"
else
    echo "📥 Pulling Phi model (this may take a few minutes)..."
    curl -X POST "http://ollama:11434/api/pull" \
        -H "Content-Type: application/json" \
        -d '{"name": "phi"}' \
        --max-time 600 || {
            echo "⚠️  Warning: Failed to pull Phi model. Will retry on first use."
        }
    echo "✅ Phi model pull initiated"
fi

echo "=========================================="
echo "🚀 Starting Flask application..."
echo "=========================================="

# Execute the main command (passed as arguments to this script)
exec "$@"
