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
COPY grid/ ./grid/
COPY v201/ ./v201/

# OCPP 2.0.1 secure track: bake the PKI (CA, server/client certs, firmware
# signing key) into /certs at build time, so every container shares one CA.
# Attacker containers deliberately do not use these CA-signed materials.
RUN python v201/secure/gen_certs.py /certs

CMD ["python", "core/csms_server4.py"]
