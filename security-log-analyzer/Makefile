# Security Log Analyzer - Makefile
# Common Docker commands for development and deployment

.PHONY: help build up down restart logs test reset shell ps clean

# Default target
help:
	@echo "Security Log Analyzer - Available Commands:"
	@echo ""
	@echo "  make build    - Build Docker images (no cache)"
	@echo "  make up       - Start all services in background"
	@echo "  make down     - Stop all services"
	@echo "  make restart  - Restart all services"
	@echo "  make logs     - Follow application logs"
	@echo "  make test     - Run all tests inside container"
	@echo "  make reset    - Reset system (requires admin token)"
	@echo "  make shell    - Open bash shell in app container"
	@echo "  make ps       - Show running containers"
	@echo "  make clean    - Stop and remove all containers, volumes, networks"
	@echo ""

# Build Docker images without cache
build:
	@echo "🔨 Building Docker images..."
	docker-compose build --no-cache
	@echo "✅ Build complete!"

# Start all services
up:
	@echo "🚀 Starting services..."
	docker-compose up -d
	@echo ""
	@echo "=========================================="
	@echo "✅ Security Log Analyzer is running!"
	@echo "=========================================="
	@echo ""
	@echo "📍 Application: http://localhost:5000"
	@echo "📍 ChromaDB:    http://localhost:8000"
	@echo "📍 Ollama:      http://localhost:11434"
	@echo ""
	@echo "📊 View logs:   make logs"
	@echo "🧪 Run tests:   make test"
	@echo "🛑 Stop:        make down"
	@echo ""

# Stop all services
down:
	@echo "🛑 Stopping services..."
	docker-compose down
	@echo "✅ Services stopped!"

# Restart all services
restart: down up

# Follow application logs
logs:
	@echo "📋 Following application logs (Ctrl+C to exit)..."
	docker-compose logs -f app

# Run tests inside container
test:
	@echo "🧪 Running tests..."
	docker-compose exec app python -m pytest tests/ -v
	@echo "✅ Tests complete!"

# Reset system (requires admin token)
reset:
	@echo "⚠️  This will clear all data from the vector database and caches."
	@read -p "Enter admin JWT token: " token; \
	curl -X POST http://localhost:5000/api/reset \
		-H "Authorization: Bearer $$token" \
		-H "Content-Type: application/json" \
		-d '{"confirm": true}'
	@echo ""

# Open shell in app container
shell:
	@echo "🐚 Opening shell in app container..."
	docker-compose exec app /bin/bash

# Show running containers
ps:
	@echo "📦 Running containers:"
	docker-compose ps

# Clean everything (including volumes)
clean:
	@echo "⚠️  WARNING: This will remove all containers, volumes, and networks!"
	@echo "⚠️  All data will be lost (database, vector store, models)!"
	@read -p "Are you sure? (yes/no): " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		echo "🧹 Cleaning up..."; \
		docker-compose down -v --remove-orphans; \
		echo "✅ Cleanup complete!"; \
	else \
		echo "❌ Cleanup cancelled."; \
	fi
