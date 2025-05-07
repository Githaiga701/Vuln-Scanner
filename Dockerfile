FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only necessary files (improves build caching)
COPY requirements.txt .
COPY scanner.py .
COPY config.ini .
COPY .env .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Set entrypoint
ENTRYPOINT ["python", "scanner.py"]