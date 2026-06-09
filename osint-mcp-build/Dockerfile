FROM kali-mcp-bash

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/usr/local
ENV PATH=$PATH:/usr/local/go/bin:/usr/local/bin

RUN apt-get update && apt-get install -y --no-install-recommends golang curl git theharvester recon-ng dnsrecon nmap whois dnsutils wpscan spiderfoot && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; go install github.com/tomnomnom/assetfinder@latest; go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest; go install github.com/owasp-amass/amass/v4/...@latest; exit 0

RUN cp /usr/local/bin/subfinder /usr/bin/subfinder 2>/dev/null; cp /usr/local/bin/assetfinder /usr/bin/assetfinder 2>/dev/null; cp /usr/local/bin/dnsx /usr/bin/dnsx 2>/dev/null; cp /usr/local/bin/amass /usr/bin/amass 2>/dev/null; exit 0

WORKDIR /app
COPY package.json .
RUN npm install
COPY src/ ./src/

CMD ["node", "src/server.js"]
