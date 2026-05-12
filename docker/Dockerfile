# docker/Dockerfile
# A Dockerfile is a recipe for building a Docker image
# Docker image = a complete snapshot of an OS + your code + all dependencies
# When you run an image, it creates a container — an isolated running process

# ─────────────────────────────────────────────
# Stage 1: Builder
# We use multi-stage builds to keep the final image small
# Stage 1 installs build tools and dependencies
# Stage 2 copies only what's needed into a clean image
# Why? Build tools (gcc, make, etc.) add ~500MB but aren't needed at runtime
# ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Set working directory inside the container
# All subsequent commands run from /app
WORKDIR /app

# Install system dependencies needed to build Python packages
# apt-get = Ubuntu's package manager
# --no-install-recommends = don't install suggested packages (saves space)
RUN apt-get update && apt-get install -y \
    gcc \           
    libpq-dev \     
    curl \          
    && rm -rf /var/lib/apt/lists/*   

# Copy requirements first (Docker layer caching optimization)
# If requirements.txt doesn't change, Docker reuses the cached pip install layer
# This makes rebuilds MUCH faster — pip install only runs when dependencies change
COPY requirements.txt .

# Install Python dependencies into /app/wheels as wheel files
# Wheels are pre-compiled — faster to install than building from source
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────
# Stage 2: Production image
# Clean, minimal runtime image
# ─────────────────────────────────────────────
FROM python:3.11-slim AS production

# Security: create a non-root user
# Running as root inside a container is dangerous
# If the container is compromised, root access could escape to the host
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Install only runtime system dependencies (not build tools)
RUN apt-get update && apt-get install -y \
    libpq5 \        
    curl \           
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from the builder stage
# This is the multi-stage magic — we get the packages without the build tools
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the port FastAPI will listen on
# EXPOSE is documentation — it doesn't actually open ports
# You open ports with -p in docker run or in docker-compose.yml
EXPOSE 8000

# Health check — Docker checks this to know if the container is healthy
# If health check fails 3 times, Docker marks container as unhealthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# The command to run when the container starts
# uvicorn = the ASGI server that runs FastAPI
# api.main:app = file path (api/main.py) and the FastAPI object (app)
# --host 0.0.0.0 = listen on all network interfaces (required inside Docker)
# --port 8000 = listen on port 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]