import express from "express";

const AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
  "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0",
];

const INTERVAL_MS = parseInt(process.env.ROTATE_INTERVAL_MS || "30000");
let currentAgent = AGENTS[Math.floor(Math.random() * AGENTS.length)];

setInterval(() => {
  currentAgent = AGENTS[Math.floor(Math.random() * AGENTS.length)];
  console.log(`[Agent Rotator] החלפה ל: ${currentAgent}`);
}, INTERVAL_MS);

const app = express();
app.get("/current-agent", (req, res) => res.json({ agent: currentAgent }));
app.listen(3001, () => console.log("Agent Rotator פועל על פורט 3001"));
