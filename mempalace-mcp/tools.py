import json
from database import save_campaign, get_campaign, list_campaigns, search_campaigns, get_patterns


def handle_save_campaign(args: dict) -> str:
    result = save_campaign(
        name=args["name"],
        target=args["target"],
        objective=args.get("objective", ""),
        tools_used=args.get("tools_used", []),
        findings=args.get("findings", ""),
        patterns=args.get("patterns", ""),
        tags=args.get("tags", [])
    )
    return json.dumps(result, ensure_ascii=False)


def handle_get_campaign(args: dict) -> str:
    result = get_campaign(int(args["campaign_id"]))
    if not result:
        return json.dumps({"error": "Campaign not found"})
    return json.dumps(result, ensure_ascii=False)


def handle_list_campaigns(args: dict) -> str:
    result = list_campaigns()
    return json.dumps(result, ensure_ascii=False)


def handle_search_campaigns(args: dict) -> str:
    result = search_campaigns(args["query"])
    return json.dumps(result, ensure_ascii=False)


def handle_get_patterns(args: dict) -> str:
    result = get_patterns()
    return json.dumps(result, ensure_ascii=False)


TOOLS = [
    {
        "name": "save_campaign",
        "description": "Save a new OSINT campaign to memory. Use this after completing or during a campaign to record the target, tools used, findings, and observed patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Short descriptive name for this campaign"},
                "target": {"type": "string", "description": "The target of the investigation (domain, person, org, IP, etc.)"},
                "objective": {"type": "string", "description": "What was the goal of this campaign"},
                "tools_used": {"type": "array", "items": {"type": "string"}, "description": "List of tools/techniques used (e.g. ['shodan', 'whois', 'theharvester'])"},
                "findings": {"type": "string", "description": "Key findings and results from the campaign"},
                "patterns": {"type": "string", "description": "Recurring patterns, behaviors, or infrastructure observed"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization (e.g. ['phishing', 'apt', 'corporate'])"}
            },
            "required": ["name", "target"]
        }
    },
    {
        "name": "get_campaign",
        "description": "Retrieve full details of a specific OSINT campaign by its ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "integer", "description": "The numeric ID of the campaign"}
            },
            "required": ["campaign_id"]
        }
    },
    {
        "name": "list_campaigns",
        "description": "List all saved OSINT campaigns, ordered by most recent first.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "search_campaigns",
        "description": "Full-text search across all campaigns — targets, findings, patterns, tags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (supports FTS5 syntax)"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "get_patterns",
        "description": "Analyze all campaigns and return recurring patterns — top tools used, common tags, and pattern summaries. Use this to learn from past investigations.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

HANDLERS = {
    "save_campaign": handle_save_campaign,
    "get_campaign": handle_get_campaign,
    "list_campaigns": handle_list_campaigns,
    "search_campaigns": handle_search_campaigns,
    "get_patterns": handle_get_patterns
}
