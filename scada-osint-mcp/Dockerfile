FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    ruby \
    ruby-dev \
    build-essential \
    libpcap-dev \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    whois \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN gem install modbus-cli

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

RUN git clone --depth=1 https://github.com/initstring/cloud_enum.git /opt/cloud_enum \
    && pip install --no-cache-dir -r /opt/cloud_enum/requirements.txt

WORKDIR /app
COPY . /app/

RUN mkdir -p /app/output /app/logs

EXPOSE 8080

CMD ["python", "-m", "src.server"]
