FROM python:3.11-slim

# nmap: port/service scanning. iputils-ping: ping fallback for LAN discovery.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user. Consequence: nmap OS detection (-O) needs root,
# so the scanner automatically falls back to a scan without it.
# /app/data holds the SQLite database (mounted as a volume by docker-compose).
RUN useradd --create-home --uid 1000 viper \
    && mkdir -p /app/data \
    && chown viper:viper /app/data
USER viper

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
