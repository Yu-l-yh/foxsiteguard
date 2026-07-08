FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY foxsiteguard/ foxsiteguard/

# Expose API port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "foxsiteguard.core.api:app", "--host", "0.0.0.0", "--port", "8000"]
