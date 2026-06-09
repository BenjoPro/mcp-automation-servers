FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-dev python3-pip python3-venv \
    nodejs npm \
    git curl wget unzip jq \
    ruby ruby-dev \
    build-essential libssl-dev libffi-dev \
    ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip

FROM base AS tools
WORKDIR /opt/tools

RUN git clone --depth 1 https://github.com/nccgroup/ScoutSuite.git /opt/tools/scoutsuite

RUN git clone --depth 1 https://github.com/aquasecurity/cloudsploit.git /opt/tools/cloudsploit \
    && cd /opt/tools/cloudsploit && npm install

RUN git clone --depth 1 https://github.com/andresriancho/enumerate-iam.git /opt/tools/enumerate-iam

RUN curl -L https://github.com/0xsha/CloudBrute/releases/download/v1.0.7/cloudbrute_1.0.7_Linux_x86_64.tar.gz \
    -o /tmp/cloudbrute.tar.gz \
    && tar -xzf /tmp/cloudbrute.tar.gz -C /usr/local/bin cloudbrute \
    && chmod +x /usr/local/bin/cloudbrute \
    && rm /tmp/cloudbrute.tar.gz

FROM tools AS final
WORKDIR /app

RUN pip install \
    mcp fastmcp boto3 botocore pydantic rich typer httpx jinja2 awscli \
    attrs jsonschema \
    pacu \
    prowler \
    truffleHog3 \
    cartography \
    aws-consoler \
    googlesearch-python requests beautifulsoup4

RUN pip install -r /opt/tools/scoutsuite/requirements.txt
RUN pip install -r /opt/tools/enumerate-iam/requirements.txt

COPY server/ ./server/
RUN mkdir -p /reports && chmod 777 /reports

ENTRYPOINT ["python", "-m", "server.main"]
