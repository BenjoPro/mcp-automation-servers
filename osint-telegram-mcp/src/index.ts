import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import * as cheerio from "cheerio";

const server = new Server(
  { name: "osint-telegram", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
  "Accept-Language": "en-US,en;q=0.9",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
};

async function fetchHtml(url: string): Promise<string> {
  const res = await axios.get(url, { headers: HEADERS, timeout: 15000, maxRedirects: 5 });
  return res.data as string;
}

async function lyzemSearch(query: string, type: "messages" | "channels" | "groups" | "bots" = "messages"): Promise<string> {
  const typeMap: Record<string, string> = { messages: "post", channels: "channel", groups: "group", bots: "bot" };
  const url = `https://lyzem.com/search?q=${encodeURIComponent(query)}&type=${typeMap[type] ?? "post"}&lang=&page=1`;
  try {
    const html = await fetchHtml(url);
    const $ = cheerio.load(html);
    const results: string[] = [];
    $(".search-result-item, .result-item, article").each((_, el) => {
      const title = $(el).find("h3, h2, .title, .channel-name").first().text().trim();
      const snippet = $(el).find("p, .description, .text, .message-text").first().text().trim();
      const link = $(el).find("a").first().attr("href");
      if (title || snippet) results.push(`📌 ${title || "(no title)"}\n${snippet ? `   ${snippet.slice(0, 200)}` : ""}${link ? `\n   🔗 ${link}` : ""}`);
    });
    if (results.length === 0) return `🔍 Lyzem "${query}" (${type}):\n\n` + $("body").text().replace(/\s+/g, " ").slice(0, 1500);
    return `🔍 Lyzem "${query}" (${type}) — ${results.length} results:\n\n${results.slice(0, 10).join("\n\n")}`;
  } catch (err: any) {
    return `❌ Lyzem failed: ${err.message}\n💡 https://lyzem.com`;
  }
}

async function tgstatChannel(channelUsername: string): Promise<string> {
  const clean = channelUsername.replace(/^@/, "").replace(/https?:\/\/t\.me\//, "");
  const url = `https://tgstat.com/channel/@${clean}`;
  try {
    const html = await fetchHtml(url);
    const $ = cheerio.load(html);
    const title = $("h1, .channel-title, .peer-title").first().text().trim();
    const description = $(".channel-description, .peer-description, .about").first().text().trim();
    const subscribers = $('[class*="subscriber"], [class*="members"]').first().text().trim();
    const er = $('[class*="engagement"], [class*="er-"]').first().text().trim();
    const category = $('[class*="categor"]').first().text().trim();
    const stats: string[] = [];
    if (title) stats.push(`📢 Channel: ${title}`);
    if (subscribers) stats.push(`👥 Subscribers: ${subscribers}`);
    if (er) stats.push(`📊 Engagement Rate: ${er}`);
    if (category) stats.push(`🏷️ Category: ${category}`);
    if (description) stats.push(`📄 Description: ${description.slice(0, 300)}`);
    stats.push(`🔗 TGStat: ${url}`);
    stats.push(`🔗 Telegram: https://t.me/${clean}`);
    if (stats.length <= 2) return `📊 TGStat @${clean}:\n\n` + $("body").text().replace(/\s+/g, " ").slice(0, 1500);
    return `📊 TGStat @${clean}:\n\n${stats.join("\n")}`;
  } catch (err: any) {
    return `❌ TGStat failed: ${err.message}\n💡 ${url}`;
  }
}

async function tgstatSearch(query: string): Promise<string> {
  const url = `https://tgstat.com/search?q=${encodeURIComponent(query)}`;
  try {
    const html = await fetchHtml(url);
    const $ = cheerio.load(html);
    const results: string[] = [];
    $("[class*='channel-card'], [class*='peer-item'], .search-item").each((_, el) => {
      const name = $(el).find("[class*='title'], h3, h2").first().text().trim();
      const subs = $(el).find("[class*='subscriber']").first().text().trim();
      const link = $(el).find("a").first().attr("href");
      const username = link?.match(/@?([\w]+)$/)?.[1];
      if (name) results.push(`📢 ${name}${subs ? ` — ${subs}` : ""}${username ? `\n   t.me/${username}` : ""}${link ? `\n   https://tgstat.com${link}` : ""}`);
    });
    if (results.length === 0) return `🔍 TGStat "${query}": No results. Visit: ${url}`;
    return `🔍 TGStat "${query}" — ${results.length} results:\n\n${results.slice(0, 10).join("\n\n")}`;
  } catch (err: any) {
    return `❌ TGStat search failed: ${err.message}`;
  }
}

async function telegagoSearch(query: string): Promise<string> {
  const telegagoLink = `https://telegago.com/?q=${encodeURIComponent(query)}`;
  const googleTme = `https://www.google.com/search?q=site%3At.me+${encodeURIComponent(query)}`;
  try {
    const html = await fetchHtml(telegagoLink);
    const $ = cheerio.load(html);
    const results: string[] = [];
    $(".gsc-result, .gs-result, .gsc-webResult").each((_, el) => {
      const title = $(el).find(".gs-title, .gsc-title").text().trim();
      const snippet = $(el).find(".gs-snippet, .gsc-snippet").text().trim();
      const link = $(el).find("a.gs-title, a.gsc-title").attr("href");
      if (title) results.push(`📌 ${title}\n${snippet ? `   ${snippet.slice(0, 200)}` : ""}${link ? `\n   🔗 ${link}` : ""}`);
    });
    if (results.length > 0) return `🔍 Telegago "${query}":\n\n${results.slice(0, 10).join("\n\n")}\n\n🔗 ${telegagoLink}`;
  } catch { }
  return `🔍 Telegago "${query}"\n\n🔗 Open in browser: ${telegagoLink}\n🔗 Google fallback: ${googleTme}\n\n💡 Telegago works best in a browser.`;
}

async function telegramLookup(username: string): Promise<string> {
  const clean = username.replace(/^@/, "").replace(/https?:\/\/t\.me\//, "");
  const url = `https://t.me/${clean}`;
  try {
    const html = await fetchHtml(url);
    const $ = cheerio.load(html);
    const title = $(".tgme_page_title span, .tgme_channel_info_header_title").text().trim();
    const description = $(".tgme_page_description").text().trim();
    const extra = $(".tgme_page_extra").text().trim();
    const photo = $(".tgme_page_photo_image img").first().attr("src");
    const lines: string[] = [`🔎 @${clean}`];
    if (title) lines.push(`📢 Name: ${title}`);
    if (extra) lines.push(`👥 ${extra}`);
    if (description) lines.push(`📄 ${description.slice(0, 400)}`);
    if (photo) lines.push(`🖼️ ${photo}`);
    lines.push(`🔗 ${url}`);
    lines.push(`📊 https://tgstat.com/channel/@${clean}`);
    return lines.join("\n");
  } catch (err: any) {
    return `❌ t.me/${clean}: ${err.message}`;
  }
}

async function telegramPostLookup(channelUsername: string, messageId: number): Promise<string> {
  const clean = channelUsername.replace(/^@/, "").replace(/https?:\/\/t\.me\//, "");
  const url = `https://t.me/${clean}/${messageId}?embed=1`;
  try {
    const html = await fetchHtml(url);
    const $ = cheerio.load(html);
    const text = $(".tgme_widget_message_text").text().trim();
    const date = $(".tgme_widget_message_date time").attr("datetime");
    const views = $(".tgme_widget_message_views").text().trim();
    const author = $(".tgme_widget_message_author_name").text().trim();
    const lines: string[] = [`📨 @${clean}/${messageId}`];
    if (author) lines.push(`👤 ${author}`);
    if (date) lines.push(`📅 ${date}`);
    if (views) lines.push(`👁️ ${views}`);
    if (text) lines.push(`\n📝 ${text.slice(0, 1000)}`);
    lines.push(`\n🔗 https://t.me/${clean}/${messageId}`);
    return lines.join("\n");
  } catch (err: any) {
    return `❌ Post fetch failed: ${err.message}`;
  }
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "lyzem_search",
      description: "Search Telegram using Lyzem — find messages, channels, groups, bots by keyword. No API key required.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          type: { type: "string", enum: ["messages", "channels", "groups", "bots"], default: "messages" },
        },
        required: ["query"],
      },
    },
    {
      name: "tgstat_channel",
      description: "Get public stats for a Telegram channel from TGStat.com. No API key required.",
      inputSchema: {
        type: "object",
        properties: { username: { type: "string", description: "Channel username e.g. @channelname" } },
        required: ["username"],
      },
    },
    {
      name: "tgstat_search",
      description: "Search Telegram channels by keyword on TGStat.com. No API key required.",
      inputSchema: {
        type: "object",
        properties: { query: { type: "string", description: "Search keywords" } },
        required: ["query"],
      },
    },
    {
      name: "telegago_search",
      description: "Search Telegram via Telegago — a Google CSE targeting t.me links. No API key required.",
      inputSchema: {
        type: "object",
        properties: { query: { type: "string", description: "Search query" } },
        required: ["query"],
      },
    },
    {
      name: "telegram_lookup",
      description: "Look up a public Telegram username — returns name, bio, subscriber count, avatar. No API key required.",
      inputSchema: {
        type: "object",
        properties: { username: { type: "string", description: "Telegram username e.g. @username" } },
        required: ["username"],
      },
    },
    {
      name: "telegram_post_lookup",
      description: "Fetch a specific public Telegram post by channel and message ID. No API key required.",
      inputSchema: {
        type: "object",
        properties: {
          channel: { type: "string", description: "Channel username" },
          message_id: { type: "number", description: "Numeric message ID" },
        },
        required: ["channel", "message_id"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let result = "";
    if (name === "lyzem_search") result = await lyzemSearch(args?.query as string, args?.type as any);
    else if (name === "tgstat_channel") result = await tgstatChannel(args?.username as string);
    else if (name === "tgstat_search") result = await tgstatSearch(args?.query as string);
    else if (name === "telegago_search") result = await telegagoSearch(args?.query as string);
    else if (name === "telegram_lookup") result = await telegramLookup(args?.username as string);
    else if (name === "telegram_post_lookup") result = await telegramPostLookup(args?.channel as string, args?.message_id as number);
    else result = `Unknown tool: ${name}`;
    return { content: [{ type: "text", text: result }] };
  } catch (err: any) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("✅ OSINT-Telegram MCP server running");
