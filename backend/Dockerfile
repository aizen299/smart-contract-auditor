FROM python:3.11-slim

WORKDIR /app

ENV PYTHONPATH=/app

RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    python3-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    slither-analyzer \
    solc-select

RUN solc-select install 0.8.24 && solc-select use 0.8.24

RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

ENV PATH="/root/.foundry/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports tmp_scans

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]