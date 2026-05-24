FROM python:3.11-slim

WORKDIR /app

# Use non-interactive matplotlib backend — no display in containers
ENV MPLBACKEND=Agg \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ ./core/
COPY attacks/ ./attacks/

CMD ["python", "core/csms_server4.py"]
