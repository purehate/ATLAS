#!/bin/bash

# Quick Start Script for ATLAS (Adversary Technique & Landscape Analysis by Sector)

set -e

echo "ATLAS - Adversary Technique & Landscape Analysis by Sector"
echo "Quick Start"
echo "=================================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "WARNING: Please edit .env and update the passwords!"
    echo "   Press Enter to continue after updating .env, or Ctrl+C to exit..."
    read
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed. Please install Docker first."
    exit 1
fi

# Check for docker compose (plugin) or docker-compose (standalone)
DOCKER_COMPOSE_CMD=""
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
    echo "Using Docker Compose plugin"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
    echo "Using docker-compose standalone"
else
    echo "ERROR: Neither 'docker compose' nor 'docker-compose' is available."
    echo "   Please install Docker Compose (plugin or standalone)."
    exit 1
fi

echo "Starting Docker services..."
$DOCKER_COMPOSE_CMD up -d

echo "Waiting for services to be healthy..."
sleep 10

echo "Running database migrations..."
$DOCKER_COMPOSE_CMD exec -T backend alembic upgrade head

echo "Seeding industries..."
$DOCKER_COMPOSE_CMD exec -T backend python scripts/seed_industries.py

echo "Ingesting MITRE ATT&CK data (this may take a few minutes)..."
$DOCKER_COMPOSE_CMD exec -T backend python scripts/ingest_mitre.py

echo ""
echo "Setup complete!"
echo ""
echo "Access the application:"
echo "   Frontend:  http://localhost:3001"
echo "   Backend:   http://localhost:6768"
echo "   API Docs:  http://localhost:6768/docs"
echo ""
echo "Admin credentials (from .env):"
echo "   Username: $(grep ADMIN_USERNAME .env | cut -d '=' -f2)"
echo ""
echo "Next steps:"
echo "   1. Open http://localhost:3001 in your browser"
echo "   2. Try calculating threats for an industry"
echo "   3. Check admin stats: curl -u admin:password http://localhost:6768/api/v1/admin/stats"
echo ""
