FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c5b694d178ad97c5e925c2d0e1a91

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/msaadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP Anomaly Detector" \
      org.opencontainers.image.description="Anomaly detection service for ZTAP (Zero Trust Access Platform)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY service.py .
COPY detector.go .
COPY README.md .

# Create directories for data and models
RUN mkdir -p /app/data /app/models

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=service.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
