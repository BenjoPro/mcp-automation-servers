FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    tor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY config/torrc /etc/tor/torrc

RUN chown -R root:root /var/lib/tor && chmod 700 /var/lib/tor

EXPOSE 8000

CMD ["sh", "-c", "tor & sleep 8 && python server.py"]
