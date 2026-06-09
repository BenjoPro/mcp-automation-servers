FROM python:3.12-slim
LABEL description="AI-Embedded-Wazuh MCP server"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "server.py"]
