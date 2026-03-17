FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install solc-select + slither
RUN pip install --no-cache-dir \
    slither-analyzer \
    solc-select

# Install solc 0.8.24
RUN solc-select install 0.8.24 && solc-select use 0.8.24

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:$PATH"
RUN foundryup

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create required dirs
RUN mkdir -p reports tmp_scans

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
