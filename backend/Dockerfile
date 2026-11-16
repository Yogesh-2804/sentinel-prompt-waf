FROM python:3.11-slim

WORKDIR /app

# Install system build tools and curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies requirement file and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt email-validator pydantic-settings

# Copy backend source code including trained models, faiss index, and company_policy.yaml
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
