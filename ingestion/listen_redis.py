"""
listen_redis.py
===============
Helper script to live-stream FlowObjects from the Redis `flow.raw` channel.
Run in a separate terminal:
  python listen_redis.py
"""
import json
import redis
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

def main():
    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, protocol=2)
    pubsub = r.pubsub()
    pubsub.subscribe("flow.raw")

    console.print(Panel(
        "[bold cyan]Subscribed to Redis channel:[/bold cyan] [yellow]flow.raw[/yellow]\n"
        "[dim]Waiting for completed FlowObjects from the ingestion pipeline...[/dim]",
        title="[bold green]REDIS FLOW STREAM[/bold green]"
    ))

    for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                formatted_json = json.dumps(data, indent=2)
                syntax = Syntax(formatted_json, "json", theme="monokai", line_numbers=False)
                
                five_tuple = data.get("five_tuple", {})
                title = f"Flow: {five_tuple.get('protocol')} {five_tuple.get('src_ip')}:{five_tuple.get('src_port')} -> {five_tuple.get('dst_ip')}:{five_tuple.get('dst_port')} (ID: {data.get('flow_id')[:8]})"
                
                console.print(Panel(syntax, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan"))
            except Exception:
                console.print(f"[yellow]{message['data']}[/yellow]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped listening.[/dim]")
