FROM python:3.11-slim

WORKDIR /app

# Use non-interactive matplotlib backend — no display in containers
ENV MPLBACKEND=Agg \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# tcpdump + procps (pkill) for per-attack pcap capture
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

COPY core/ ./core/
COPY attacks/ ./attacks/

CMD ["python", "core/csms_server4.py"]
