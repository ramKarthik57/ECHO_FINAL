FROM python:3.11-slim

LABEL maintainer="ramKarthik57 <https://github.com/ramKarthik57>"
LABEL description="ECHO - Encrypted Communication Heuristic Observer"
LABEL version="1.0.0"

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tshark \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY backend/ ./backend/
COPY dashboard/ ./dashboard/
COPY utils/ ./utils/
COPY run_analysis.py .

# Create data directory
RUN mkdir -p data

# Expose ports
EXPOSE 8000 8001

# Default: start the API server
CMD ["python", "backend/api_server.py"]
