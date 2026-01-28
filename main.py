# main.py

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from rich.live import Live
from rich import print as rprint

# Import our custom modules
from modules.config import ConfigManager
from modules.engine import ScannerEngine, IpManager
from modules.ui import Dashboard

def main():
    # 1. Setup
    config = ConfigManager.load_config()
    subnets = IpManager.load_subnets(config['subnets_file'])
    targets = IpManager.generate_targets(subnets, config['randomize'])
    
    if not targets:
        rprint("[bold red]No targets found. Check subnets.txt[/bold red]")
        sys.exit(1)

    rprint(f"\n[yellow]Starting scan on {len(targets)} IPs...[/yellow]")
    
    # 2. Initialize
    engine = ScannerEngine(config)
    dashboard = Dashboard()
    stop_event = threading.Event()
    stats = {"scanned": 0, "found": 0}
    results = []

    # 3. Execution Loop
    try:
        with Live(refresh_per_second=4) as live:
            with ThreadPoolExecutor(max_workers=config['workers']) as executor:
                futures = {executor.submit(engine.check_ip, ip, stop_event): ip for ip in targets}
                
                for future in futures:
                    if stop_event.is_set(): break
                    try:
                        result = future.result()
                        stats["scanned"] += 1
                        
                        if result:
                            stats["found"] += 1
                            results.append(result)
                            dashboard.add_row(result)
                        
                        live.update(dashboard.get_layout(stats))
                    except KeyboardInterrupt:
                        raise
                        
    except KeyboardInterrupt:
        stop_event.set()
        rprint("\n[red]Scan Aborted![/red]")

    # 4. Save Results
    if results:
        results.sort(key=lambda x: x['latency'])
        with open("working_ips.txt", "w") as f:
            for res in results: f.write(f"{res['ip']}\n")
        rprint(f"\n[green]✓ Saved {len(results)} IPs to working_ips.txt[/green]")

if __name__ == "__main__":
    main()
