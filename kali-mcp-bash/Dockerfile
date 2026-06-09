FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.js .
RUN npm install @modelcontextprotocol/sdk
CMD ["node", "server.js"]
