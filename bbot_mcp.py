import asyncio
from mcp.server.fastmcp import FastMCP
from bbot.scanner import Scanner

# Initialize FastMCP server
mcp = FastMCP("BBOT Recon Server")

# Dictionary to track active scans
active_scans = {}

@mcp.tool()
async def start_scan(target: str, presets: str = "subdomain-enum", modules: str = "") -> str:
    """
    Starts a BBOT reconnaissance scan.
    :param target: The target domain or IP (e.g., 'example.com')
    :param presets: BBOT presets to use (e.g., 'subdomain-enum', 'spider')
    :param modules: Specific modules to enable (comma-separated)
    """
    try:
        # Prepare modules list if provided
        module_list = [m.strip() for m in modules.split(",")] if modules else []
        preset_list = [p.strip() for p in presets.split(",")]

        # Initialize BBOT Scanner
        # Note: In standard BBOT API, Scanner is often synchronous; 
        # we run it in a thread to avoid blocking the MCP loop.
        scan = Scanner(target, presets=preset_list, modules=module_list)
        
        # Start scan in the background
        loop = asyncio.get_event_loop()
        task = loop.run_in_executor(None, scan.start)
        
        scan_id = scan.name
        active_scans[scan_id] = {
            "scanner": scan,
            "task": task,
            "status": "running"
        }

        return f"Scan '{scan_id}' started against {target} using presets: {presets}."
    except Exception as e:
        return f"Failed to start scan: {str(e)}"

@mcp.tool()
async def get_scan_status(scan_name: str) -> str:
    """Check the status and basic stats of a specific BBOT scan."""
    if scan_name not in active_scans:
        return f"No active scan found with name '{scan_name}'"
    
    scan_info = active_scans[scan_name]
    scanner = scan_info["scanner"]
    
    # Check if background task is done
    if scan_info["task"].done():
        scan_info["status"] = "finished"

    stats = f"Status: {scan_info['status']}\n"
    stats += f"Events Processed: {len(scanner.manager.events)}"
    return stats

@mcp.tool()
async def list_findings(scan_name: str, limit: int = 10) -> str:
    """
    Retrieve the most recent findings (events) from a scan.
    :param scan_name: The unique name of the scan (e.g., 'fuzzy_gandalf')
    :param limit: Number of findings to return.
    """
    if scan_name not in active_scans:
        return f"Scan '{scan_name}' not found."

    scanner = active_scans[scan_name]["scanner"]
    events = list(scanner.manager.events)[-limit:]
    
    if not events:
        return "No findings yet."

    results = []
    for e in events:
        results.append(f"[{e.type}] {e.data}")
    
    return "\n".join(results)

if __name__ == "__main__":
    mcp.run(transport="stdio")
