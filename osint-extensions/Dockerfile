FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget ca-certificates golang-go \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN go install github.com/lc/gau/v2/cmd/gau@latest

RUN git clone --depth 1 https://github.com/sherlock-project/sherlock /opt/sherlock \
    && pip install --no-cache-dir /opt/sherlock

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV FOFA_EMAIL=""
ENV FOFA_API_KEY=""
ENV ZOOMEYE_API_KEY=""

ENTRYPOINT ["python3", "server.py"]
