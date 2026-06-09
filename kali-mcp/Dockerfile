FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*
RUN npm install -g @modelcontextprotocol/server-filesystem
CMD ["mcp-server-filesystem", "/"]
