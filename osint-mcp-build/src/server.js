const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
const { execSync, exec } = require('child_process');
const fetch = require('node-fetch');

const SHODAN_API_KEY    = process.env.SHODAN_API_KEY    || '';
const CENSYS_API_ID     = process.env.CENSYS_API_ID     || '';
const CENSYS_API_SECRET = process.env.CENSYS_API_SECRET || '';

function run(cmd, timeoutMs = 120000) {
  try {
    return execSync(cmd, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }).toString().trim();
  } catch (e) {
    return e.stdout ? e.stdout.toString().trim() : e.message;
  }
}

async function runAsync(cmd, timeoutMs = 120000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve(stdout || stderr || (err && err.message) || '');
    });
  });
}

async function httpGet(url, headers = {}) {
  try {
    const res = await fetch(url, { headers, timeout: 15000 });
    const text = await res.text();
    return { status: res.status, body: text };
  } catch (e) {
    return { status: 0, body: e.message };
  }
}

function ok(text)  { return { content: [{ type: 'text', text: String(text) }] }; }
function err(text) { return { content: [{ type: 'text', text: '❌ ' + String(text) }] }; }

const TOOLS = [
  {
    name: 'google_dork',
    description: 'Build a Google dork query for OSINT. Returns ready-to-use dork URL.',
    inputSchema: {
      type: 'object',
      properties: {
        target:    { type: 'string', description: 'Domain or keyword to investigate' },
        dork_type: { type: 'string', description: 'Type: files|login|config|emails|subdomains|cameras|databases|custom', enum: ['files','login','config','emails','subdomains','cameras','databases','custom'] },
        custom:    { type: 'string', description: 'Custom dork string (when dork_type=custom)' },
        filetype:  { type: 'string', description: 'File extension (pdf, xls, doc, sql, env, etc.)' }
      },
      required: ['target', 'dork_type']
    }
  },
  {
    name: 'theharvester',
    description: 'Run theHarvester to gather emails, subdomains, IPs from public sources.',
    inputSchema: {
      type: 'object',
      properties: {
        domain:  { type: 'string', description: 'Target domain (e.g. example.com)' },
        sources: { type: 'string', description: 'Data sources: all, google, bing, linkedin, crtsh, dnsdumpster, etc.', default: 'all' },
        limit:   { type: 'number', description: 'Max results per source (default 200)', default: 200 }
      },
      required: ['domain']
    }
  },
  {
    name: 'recon_ng',
    description: 'Run a Recon-ng module against a target.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target domain or company' },
        module: { type: 'string', description: 'Module path e.g. recon/domains-hosts/hackertarget, or "list"' }
      },
      required: ['target', 'module']
    }
  },
  {
    name: 'amass',
    description: 'Run Amass for subdomain enumeration and ASN/IP discovery.',
    inputSchema: {
      type: 'object',
      properties: {
        domain:  { type: 'string', description: 'Target domain' },
        mode:    { type: 'string', description: 'enum | intel', default: 'enum' },
        passive: { type: 'boolean', description: 'Passive mode only (default true)', default: true },
        timeout: { type: 'number', description: 'Timeout in minutes (default 5)', default: 5 }
      },
      required: ['domain']
    }
  },
  {
    name: 'shodan_search',
    description: 'Search Shodan for hosts, services, open ports, banners, CVEs. Requires SHODAN_API_KEY.',
    inputSchema: {
      type: 'object',
      properties: {
        query:  { type: 'string', description: 'Shodan search query' },
        type:   { type: 'string', description: 'search|host|count|dns|myip|exploits', enum: ['search','host','count','dns','myip','exploits'], default: 'search' },
        facets: { type: 'string', description: 'Comma-separated facets (e.g. org,os,port)' },
        page:   { type: 'number', description: 'Result page (default 1)', default: 1 }
      },
      required: ['query']
    }
  },
  {
    name: 'censys_search',
    description: 'Search Censys for hosts and certificates. Requires CENSYS_API_ID and CENSYS_API_SECRET.',
    inputSchema: {
      type: 'object',
      properties: {
        query:  { type: 'string', description: 'Censys search query' },
        index:  { type: 'string', description: 'hosts|certificates', enum: ['hosts','certificates'], default: 'hosts' },
        fields: { type: 'array',  description: 'Fields to return', items: { type: 'string' } },
        pages:  { type: 'number', description: 'Number of pages (default 1)', default: 1 }
      },
      required: ['query']
    }
  },
  {
    name: 'spiderfoot_scan',
    description: 'Run a SpiderFoot CLI scan for automated OSINT collection.',
    inputSchema: {
      type: 'object',
      properties: {
        target:  { type: 'string', description: 'Target: domain, IP, email, or username' },
        modules: { type: 'string', description: 'Comma-separated modules or "all"', default: 'sfp_dnsresolve,sfp_ssl,sfp_whois,sfp_subdomainfinder' },
        timeout: { type: 'number', description: 'Timeout in minutes (default 5)', default: 5 }
      },
      required: ['target']
    }
  },
  {
    name: 'crtsh',
    description: 'Query crt.sh certificate transparency logs for subdomains and related domains.',
    inputSchema: {
      type: 'object',
      properties: {
        domain:  { type: 'string', description: 'Domain to search' },
        expired: { type: 'boolean', description: 'Include expired certs (default false)', default: false }
      },
      required: ['domain']
    }
  },
  {
    name: 'whois_lookup',
    description: 'WHOIS lookup for domain registration info, registrar, registrant email.',
    inputSchema: {
      type: 'object',
      properties: {
        target:     { type: 'string', description: 'Domain or IP address' },
        historical: { type: 'boolean', description: 'Also check whoxy.com for historical data', default: false }
      },
      required: ['target']
    }
  },
  {
    name: 'dns_recon',
    description: 'Comprehensive DNS recon: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV records.',
    inputSchema: {
      type: 'object',
      properties: {
        domain:       { type: 'string', description: 'Target domain' },
        record_types: { type: 'array', description: 'Record types to query', items: { type: 'string' }, default: ['A','AAAA','MX','TXT','NS','SOA','CNAME','SRV'] },
        brute:        { type: 'boolean', description: 'Enable subdomain brute-force', default: false }
      },
      required: ['domain']
    }
  },
  {
    name: 'viewdns',
    description: 'ViewDNS.info tools: IP history, reverse IP, DNS records, port scan, hosting provider.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Domain or IP address' },
        tool:   { type: 'string', description: 'iphistory|reverseip|dnsrecord|portscan|whois|reversemx|ipinfo', enum: ['iphistory','reverseip','dnsrecord','portscan','whois','reversemx','ipinfo'], default: 'iphistory' }
      },
      required: ['target', 'tool']
    }
  },
  {
    name: 'web_archive',
    description: 'Check Wayback Machine for historical snapshots of a website.',
    inputSchema: {
      type: 'object',
      properties: {
        url:   { type: 'string', description: 'URL to check (e.g. https://example.com)' },
        limit: { type: 'number', description: 'Number of snapshots to list (default 20)', default: 20 }
      },
      required: ['url']
    }
  },
  {
    name: 'virustotal',
    description: 'Query VirusTotal for domain/IP reputation, subdomains, passive DNS.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Domain, IP, hash, or URL' },
        type:   { type: 'string', description: 'domain|ip|file|url|subdomains|relations', enum: ['domain','ip','file','url','subdomains','relations'], default: 'domain' }
      },
      required: ['target']
    }
  },
  {
    name: 'hibp',
    description: 'Check Have I Been Pwned for breached email addresses.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Email address or domain' },
        type:   { type: 'string', description: 'email|domain', enum: ['email','domain'], default: 'email' }
      },
      required: ['target']
    }
  },
  {
    name: 'cavalier_osint',
    description: 'Query Hudson Rock Cavalier API for infostealer-compromised credentials by email.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Email address to check' }
      },
      required: ['email']
    }
  },
  {
    name: 'dnsdumpster',
    description: 'Full DNS map via HackerTarget API: hosts, DNS records, hosting providers.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Target domain to map' }
      },
      required: ['domain']
    }
  },
  {
    name: 'wordpress_recon',
    description: 'Enumerate WordPress users, plugins, themes via REST API and WPScan.',
    inputSchema: {
      type: 'object',
      properties: {
        url:  { type: 'string', description: 'WordPress site URL (e.g. https://example.com)' },
        mode: { type: 'string', description: 'users|plugins|themes|all|wpscan', enum: ['users','plugins','themes','all','wpscan'], default: 'all' }
      },
      required: ['url']
    }
  },
  {
    name: 'subdomain_enum',
    description: 'Enumerate subdomains using subfinder, assetfinder, crt.sh, amass, and dnsx.',
    inputSchema: {
      type: 'object',
      properties: {
        domain:  { type: 'string', description: 'Target domain' },
        tools:   { type: 'array', description: 'Tools: subfinder, assetfinder, crtsh, amass, dnsx', items: { type: 'string' }, default: ['subfinder','assetfinder','crtsh','dnsx'] },
        resolve: { type: 'boolean', description: 'Resolve and verify live subdomains (default true)', default: true }
      },
      required: ['domain']
    }
  },
  {
    name: 'osint_install',
    description: 'Install or verify OSINT tools: theharvester, amass, subfinder, assetfinder, dnsx, httpx, spiderfoot, recon-ng, wpscan, dnsrecon.',
    inputSchema: {
      type: 'object',
      properties: {
        tools: { type: 'array', description: 'Tools to install, or ["all"]', items: { type: 'string' }, default: ['all'] }
      }
    }
  }
];

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handle_google_dork({ target, dork_type, custom, filetype }) {
  const base = 'https://www.google.com/search?q=';
  let dork = '';
  switch (dork_type) {
    case 'files':      dork = `site:${target} filetype:${filetype || 'pdf OR xls OR doc OR txt OR csv OR sql OR env OR config OR bak'}`; break;
    case 'login':      dork = `site:${target} inurl:"login OR admin OR signin OR portal OR dashboard"`; break;
    case 'config':     dork = `site:${target} ext:conf OR ext:env OR ext:yml OR ext:yaml OR ext:ini OR ext:cfg`; break;
    case 'emails':     dork = `site:${target} intext:"@${target}"`; break;
    case 'subdomains': dork = `site:*.${target} -www`; break;
    case 'cameras':    dork = `site:${target} inurl:"view/index.shtml" OR inurl:"ViewerFrame?Mode="`; break;
    case 'databases':  dork = `site:${target} ext:sql OR ext:db OR ext:sqlite OR inurl:"phpmyadmin"`; break;
    case 'custom':     dork = custom || `site:${target}`; break;
    default:           dork = `site:${target}`;
  }
  return ok(`🔍 Google Dork Query\n${'─'.repeat(60)}\nDork:  ${dork}\n\nURL:   ${base + encodeURIComponent(dork)}\n\n💡 Open in browser or use: curl -A "Mozilla/5.0" "<URL>"`);
}

async function handle_theharvester({ domain, sources = 'all', limit = 200 }) {
  const srcFlag = sources === 'all'
    ? 'baidu,bing,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,rapiddns,subdomainfinder,urlscan,yahoo'
    : sources;
  const output = await runAsync(`theHarvester -d ${domain} -b ${srcFlag} -l ${limit} 2>&1`, 90000);
  return ok(`🌾 theHarvester — ${domain}\n${'─'.repeat(60)}\n${output}`);
}

async function handle_recon_ng({ target, module }) {
  if (module === 'list') {
    const out = run('ls /usr/share/recon-ng/modules/recon/ 2>/dev/null || echo "recon-ng not found"');
    return ok(`📦 Recon-ng modules:\n${out}`);
  }
  const script = `/tmp/recon_${Date.now()}.rc`;
  run(`printf 'workspaces create tmp\\ndb insert domains name=${target}\\nmodules load ${module}\\nrun\\nexit\\n' > ${script}`);
  const output = await runAsync(`recon-ng -r ${script} 2>&1`, 60000);
  run(`rm -f ${script}`);
  return ok(`🔭 Recon-ng [${module}] — ${target}\n${'─'.repeat(60)}\n${output}`);
}

async function handle_amass({ domain, mode = 'enum', passive = true, timeout = 5 }) {
  const cmd = mode === 'intel'
    ? `amass intel -whois -d ${domain} -timeout ${timeout} 2>&1`
    : `amass enum ${passive ? '-passive' : ''} -d ${domain} -timeout ${timeout} 2>&1`;
  const output = await runAsync(cmd, (timeout + 1) * 60 * 1000);
  return ok(`🕵️ Amass [${mode}] — ${domain}\n${'─'.repeat(60)}\n${output}`);
}

async function handle_shodan({ query, type = 'search', facets, page = 1 }) {
  if (!SHODAN_API_KEY) return err('SHODAN_API_KEY not set.');
  let url;
  switch (type) {
    case 'host':     url = `https://api.shodan.io/shodan/host/${encodeURIComponent(query)}?key=${SHODAN_API_KEY}`; break;
    case 'count':    url = `https://api.shodan.io/shodan/host/count?key=${SHODAN_API_KEY}&query=${encodeURIComponent(query)}${facets ? '&facets='+facets : ''}`; break;
    case 'dns':      url = `https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(query)}&key=${SHODAN_API_KEY}`; break;
    case 'myip':     url = `https://api.shodan.io/tools/myip?key=${SHODAN_API_KEY}`; break;
    case 'exploits': url = `https://exploits.shodan.io/api/search?query=${encodeURIComponent(query)}&key=${SHODAN_API_KEY}`; break;
    default:         url = `https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=${encodeURIComponent(query)}&page=${page}${facets ? '&facets='+facets : ''}`;
  }
  const res = await httpGet(url);
  if (res.status !== 200) return err(`Shodan HTTP ${res.status}: ${res.body.substring(0, 300)}`);
  try {
    const data = JSON.parse(res.body);
    if (type === 'search') {
      const hosts = (data.matches || []).map(h =>
        `IP: ${h.ip_str}  Port: ${h.port}  Org: ${h.org||'-'}  OS: ${h.os||'-'}  Country: ${h.location?.country_name||'-'}\n  Product: ${h.product||'-'}  Banner: ${(h.data||'').substring(0,100)}`
      ).join('\n\n');
      return ok(`🔍 Shodan: "${query}" — Total: ${data.total||0}\n${'─'.repeat(60)}\n${hosts}`);
    }
    return ok(`🔍 Shodan [${type}]:\n${JSON.stringify(data, null, 2)}`);
  } catch { return ok(`Shodan:\n${res.body.substring(0, 2000)}`); }
}

async function handle_censys({ query, index = 'hosts', fields, pages = 1 }) {
  if (!CENSYS_API_ID || !CENSYS_API_SECRET) return err('CENSYS_API_ID / CENSYS_API_SECRET not set.');
  const auth = Buffer.from(`${CENSYS_API_ID}:${CENSYS_API_SECRET}`).toString('base64');
  const headers = { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' };
  const endpoint = index === 'certificates'
    ? 'https://search.censys.io/api/v2/certificates/search'
    : 'https://search.censys.io/api/v2/hosts/search';
  let results = [], cursor = null;
  for (let p = 0; p < pages; p++) {
    const body = { q: query, per_page: 50 };
    if (fields && fields.length) body.fields = fields;
    if (cursor) body.cursor = cursor;
    const res = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body), timeout: 15000 });
    const data = await res.json();
    if (!res.ok) return err(`Censys HTTP ${res.status}: ${JSON.stringify(data)}`);
    results.push(...(data.result?.hits || []));
    cursor = data.result?.links?.next;
    if (!cursor) break;
  }
  const formatted = results.map((h, i) => {
    const services = (h.services || []).map(s => `${s.port}/${s.transport_protocol} ${s.service_name||''}`).join(', ');
    return `[${i+1}] IP: ${h.ip||'-'}  Country: ${h.location?.country||'-'}  ASN: ${h.autonomous_system?.name||'-'}\n    Services: ${services||'-'}`;
  }).join('\n\n');
  return ok(`🔬 Censys [${index}]: "${query}" — ${results.length} results\n${'─'.repeat(60)}\n${formatted}`);
}

async function handle_spiderfoot({ target, modules, timeout = 5 }) {
  const mods = modules || 'sfp_dnsresolve,sfp_ssl,sfp_whois,sfp_subdomainfinder';
  const output = await runAsync(`timeout ${timeout * 60} spiderfoot -s "${target}" -m "${mods}" -o json -q 2>&1`, (timeout + 1) * 60 * 1000);
  return ok(`🕷️ SpiderFoot — ${target}\nModules: ${mods}\n${'─'.repeat(60)}\n${output.substring(0, 8000)}`);
}

async function handle_crtsh({ domain, expired = false }) {
  const res = await httpGet(`https://crt.sh/?q=${encodeURIComponent('%.'+domain)}&output=json`);
  if (res.status !== 200) return err(`crt.sh HTTP ${res.status}`);
  try {
    const certs = JSON.parse(res.body);
    const now = new Date();
    const filtered = expired ? certs : certs.filter(c => new Date(c.not_after) > now);
    const unique = [...new Set(filtered.flatMap(c => (c.name_value||'').split('\n').map(n => n.trim()).filter(n => n && n.includes(domain))))].sort();
    const summary = filtered.slice(0, 30).map(c =>
      `ID: ${c.id}  CN: ${c.common_name}  Issued: ${c.not_before?.substring(0,10)}  Expires: ${c.not_after?.substring(0,10)}\n  Names: ${(c.name_value||'').replace(/\n/g,', ').substring(0,120)}`
    ).join('\n\n');
    return ok(`🔒 crt.sh — ${domain}\nCerts: ${filtered.length}  |  Unique subdomains: ${unique.length}\n\n📋 Subdomains:\n${unique.slice(0,100).join('\n')}\n\n${'─'.repeat(60)}\n${summary}`);
  } catch { return ok(`crt.sh:\n${res.body.substring(0, 3000)}`); }
}

async function handle_whois({ target, historical = false }) {
  const out = run(`whois ${target} 2>&1`);
  let extra = '';
  if (historical) {
    const res = await httpGet(`https://api.whoxy.com/?key=whoxy_free&whois=${encodeURIComponent(target)}`);
    extra = `\n\n🕰️ Whoxy:\n${res.body.substring(0, 2000)}`;
  }
  return ok(`📋 WHOIS — ${target}\n${'─'.repeat(60)}\n${out}${extra}`);
}

async function handle_dns_recon({ domain, record_types, brute = false }) {
  const types = (record_types && record_types.length) ? record_types : ['A','AAAA','MX','TXT','NS','SOA','SRV'];
  const digOut = types.map(t => `echo "=== ${t} ==="; dig +short ${t} ${domain} 2>&1`).join('; ');
  const dig = run(digOut);
  const dnsrecon = await runAsync(`timeout 30 dnsrecon -d ${domain} -t std 2>&1`, 90000);
  let bruteOut = '';
  if (brute) bruteOut = '\n\n🔨 Brute:\n' + await runAsync(`dnsrecon -d ${domain} -t brt 2>&1`, 120000);
  return ok(`🌐 DNS Recon — ${domain}\n${'─'.repeat(60)}\n📌 dig:\n${dig}\n\n🔍 dnsrecon:\n${dnsrecon.substring(0,4000)}${bruteOut}`);
}

async function handle_viewdns({ target, tool }) {
  const url = `https://api.viewdns.info/${tool}/?domain=${target}&apikey=free&output=json`;
  const res = await httpGet(url);
  if (res.status !== 200 || res.body.includes('"error"')) {
    const curl = run(`curl -sA "Mozilla/5.0" "https://viewdns.info/${tool}/?domain=${target}" 2>&1 | head -80`);
    return ok(`🌐 ViewDNS [${tool}] — ${target}\n${curl}`);
  }
  return ok(`🌐 ViewDNS [${tool}] — ${target}\n${'─'.repeat(60)}\n${res.body.substring(0, 3000)}`);
}

async function handle_web_archive({ url, limit = 20 }) {
  const target = url.replace(/^https?:\/\//, '');
  const snap = await httpGet(`https://archive.org/wayback/available?url=${encodeURIComponent(target)}`);
  const cdx  = await httpGet(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(target)}&output=text&limit=${limit}&fl=timestamp,statuscode,mimetype,original&collapse=digest`);
  let snapParsed = '';
  try { snapParsed = JSON.stringify(JSON.parse(snap.body), null, 2); } catch { snapParsed = snap.body; }
  return ok(`🏛️ Web Archive — ${target}\n${'─'.repeat(60)}\n📸 Latest:\n${snapParsed}\n\n📅 History:\n${cdx.body.substring(0, 3000)}`);
}

async function handle_virustotal({ target, type = 'domain' }) {
  const base = 'https://www.virustotal.com/api/v3';
  const endpoints = {
    domain:    `${base}/domains/${encodeURIComponent(target)}`,
    ip:        `${base}/ip_addresses/${encodeURIComponent(target)}`,
    file:      `${base}/files/${encodeURIComponent(target)}`,
    subdomains:`${base}/domains/${encodeURIComponent(target)}/subdomains`,
    relations: `${base}/domains/${encodeURIComponent(target)}/relations`,
  };
  const url = endpoints[type] || endpoints.domain;
  const res = await httpGet(url, { 'x-apikey': process.env.VT_API_KEY || '' });
  if (res.status === 401) return ok(`🦠 VirusTotal — ${target}\n💡 Set VT_API_KEY for full data.\nView: https://www.virustotal.com/gui/${type}/${target}`);
  try {
    const d = JSON.parse(res.body);
    const a = d.data?.attributes || {};
    const s = a.last_analysis_stats || {};
    return ok(`🦠 VirusTotal [${type}] — ${target}\nReputation: ${a.reputation||0}\nMalicious: ${s.malicious||0}  Suspicious: ${s.suspicious||0}  Clean: ${s.harmless||0}\nCategories: ${JSON.stringify(a.categories||{})}\nTags: ${(a.tags||[]).join(', ')}\n\nhttps://www.virustotal.com/gui/${type}/${target}`);
  } catch { return ok(`VirusTotal:\n${res.body.substring(0, 2000)}`); }
}

async function handle_hibp({ target, type = 'email' }) {
  const headers = { 'User-Agent': 'osint-mcp/1.0', 'hibp-api-key': process.env.HIBP_API_KEY || '' };
  const url = type === 'email'
    ? `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}?truncateResponse=false`
    : `https://haveibeenpwned.com/api/v3/breaches`;
  const res = await httpGet(url, headers);
  if (res.status === 404) return ok(`✅ HIBP — ${target}: No breaches found.`);
  if (res.status === 401) return ok(`⚠️ HIBP requires API key.\nCheck: https://haveibeenpwned.com/account/${encodeURIComponent(target)}`);
  try {
    const breaches = JSON.parse(res.body);
    const list = Array.isArray(breaches)
      ? breaches.map(b => `💥 ${b.Name} (${b.BreachDate}): ${b.PwnCount?.toLocaleString()} accounts\n   Data: ${(b.DataClasses||[]).join(', ')}`).join('\n\n')
      : JSON.stringify(breaches, null, 2);
    return ok(`⚠️ HIBP — ${target}\nBreaches: ${Array.isArray(breaches)?breaches.length:'?'}\n${'─'.repeat(60)}\n${list}`);
  } catch { return ok(`HIBP:\n${res.body.substring(0, 2000)}`); }
}

async function handle_cavalier({ email }) {
  const res = await httpGet(`https://cavalier.hudsonrock.com/api/json/v2/preview/search-by-login/osint-tools?email=${encodeURIComponent(email)}`, { 'User-Agent': 'osint-mcp/1.0' });
  try { return ok(`🔐 Hudson Rock — ${email}\n${'─'.repeat(60)}\n${JSON.stringify(JSON.parse(res.body), null, 2)}`); }
  catch { return ok(`Hudson Rock:\n${res.body.substring(0, 2000)}`); }
}

async function handle_dnsdumpster({ domain }) {
  const [hosts, dns, reverse] = await Promise.all([
    httpGet(`https://api.hackertarget.com/hostsearch/?q=${domain}`),
    httpGet(`https://api.hackertarget.com/dnslookup/?q=${domain}`),
    httpGet(`https://api.hackertarget.com/reversedns/?q=${domain}`)
  ]);
  return ok(`🗺️ DNS Dumpster — ${domain}\n${'─'.repeat(60)}\n🖥️ Hosts:\n${hosts.body.substring(0,2000)}\n\n📡 DNS:\n${dns.body.substring(0,2000)}\n\n🔄 Reverse DNS:\n${reverse.body.substring(0,1000)}`);
}

async function handle_wordpress({ url, mode = 'all' }) {
  const base = url.replace(/\/$/, '');
  const results = {};
  if (mode === 'users' || mode === 'all') {
    const r = await httpGet(`${base}/wp-json/wp/v2/users?per_page=100`);
    try { results.users = JSON.parse(r.body).map(u => `ID:${u.id} | ${u.name} | slug:${u.slug}`); }
    catch { results.users = [r.body.substring(0, 500)]; }
  }
  if (mode === 'wpscan' || mode === 'all') {
    results.wpscan = (await runAsync(`wpscan --url ${url} --enumerate u,p,t --no-update 2>&1`, 90000)).substring(0, 4000);
  }
  return ok(`🔌 WordPress — ${url}\n${'─'.repeat(60)}\n${JSON.stringify(results, null, 2)}`);
}

async function handle_subdomain_enum({ domain, tools, resolve = true }) {
  const toolList = (tools && tools.length) ? tools : ['subfinder','assetfinder','crtsh','dnsx'];
  const results = new Set();
  const log = [];

  if (toolList.includes('subfinder')) {
    const out = await runAsync(`subfinder -d ${domain} -silent 2>&1`, 60000);
    out.split('\n').filter(l => l.trim()).forEach(l => results.add(l.trim()));
    log.push(`subfinder: ${out.split('\n').filter(l=>l.trim()).length}`);
  }
  if (toolList.includes('assetfinder')) {
    const out = await runAsync(`assetfinder --subs-only ${domain} 2>&1`, 60000);
    out.split('\n').filter(l => l.includes(domain)).forEach(l => results.add(l.trim()));
    log.push(`assetfinder: ${out.split('\n').filter(l=>l.includes(domain)).length}`);
  }
  if (toolList.includes('crtsh')) {
    const res = await httpGet(`https://crt.sh/?q=%25.${domain}&output=json`);
    try { JSON.parse(res.body).forEach(c => (c.name_value||'').split('\n').forEach(n => { if (n.includes(domain)) results.add(n.trim()); })); }
    catch {}
    log.push('crtsh: done');
  }
  if (toolList.includes('amass')) {
    const out = await runAsync(`amass enum -passive -d ${domain} -timeout 3 2>&1`, 240000);
    out.split('\n').filter(l => l.includes(domain)).forEach(l => results.add(l.trim()));
    log.push(`amass: ${out.split('\n').filter(l=>l.includes(domain)).length}`);
  }

  const allSubs = [...results].sort();
  let resolved = '';
  if (resolve && allSubs.length > 0 && toolList.includes('dnsx')) {
    const tmp = `/tmp/subs_${Date.now()}.txt`;
    run(`printf '${allSubs.slice(0,500).join('\\n')}' > ${tmp}`);
    const dnsxOut = await runAsync(`dnsx -l ${tmp} -silent 2>&1`, 60000);
    run(`rm -f ${tmp}`);
    resolved = `\n\n✅ Live (dnsx):\n${dnsxOut.substring(0, 3000)}`;
  }
  return ok(`🔎 Subdomains — ${domain}\n${log.join(' | ')}\nTotal unique: ${results.size}\n\n${allSubs.slice(0,300).join('\n')}${resolved}`);
}

async function handle_install({ tools }) {
  const all = ['theharvester','amass','subfinder','assetfinder','dnsx','httpx','spiderfoot','recon-ng','wpscan','dnsrecon','nmap'];
  const toInstall = (tools && tools.length && !tools.includes('all')) ? tools : all;
  let log = `🔧 Verifying tools:\n`;
  for (const t of toInstall) {
    const found = run(`which ${t} 2>/dev/null || echo "NOT FOUND"`);
    log += `  ${t}: ${found}\n`;
  }
  return ok(log);
}

// ── Server ────────────────────────────────────────────────────────────────────
const server = new Server(
  { name: 'osint-mcp', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    switch (name) {
      case 'google_dork':      return await handle_google_dork(args);
      case 'theharvester':     return await handle_theharvester(args);
      case 'recon_ng':         return await handle_recon_ng(args);
      case 'amass':            return await handle_amass(args);
      case 'shodan_search':    return await handle_shodan(args);
      case 'censys_search':    return await handle_censys(args);
      case 'spiderfoot_scan':  return await handle_spiderfoot(args);
      case 'crtsh':            return await handle_crtsh(args);
      case 'whois_lookup':     return await handle_whois(args);
      case 'dns_recon':        return await handle_dns_recon(args);
      case 'viewdns':          return await handle_viewdns(args);
      case 'web_archive':      return await handle_web_archive(args);
      case 'virustotal':       return await handle_virustotal(args);
      case 'hibp':             return await handle_hibp(args);
      case 'cavalier_osint':   return await handle_cavalier(args);
      case 'dnsdumpster':      return await handle_dnsdumpster(args);
      case 'wordpress_recon':  return await handle_wordpress(args);
      case 'subdomain_enum':   return await handle_subdomain_enum(args);
      case 'osint_install':    return await handle_install(args);
      default:                 return err(`Unknown tool: ${name}`);
    }
  } catch (e) {
    return err(`${name} crashed: ${e.message}`);
  }
});

const transport = new StdioServerTransport();
server.connect(transport);
process.stderr.write('OSINT MCP Server started\n');
