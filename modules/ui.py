from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout

class Dashboard:
    """Manages the Terminal User Interface (TUI)."""
    
    def __init__(self):
        # Create table to display results
        self.table = Table(title="Working IPs", style="cyan", box=None)
        self.table.add_column("IP Address", style="bold white")
        self.table.add_column("Latency", style="green")
        self.table.add_column("Time", style="dim")

    def get_layout(self, stats):
        """Updates the dashboard layout with new stats."""
        layout = Layout()
        
        # Split the screen into two sections: top (header) and bottom (body)
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body")
        )
        
        # Fixed section (using [/] to close tags to prevent markup errors)
        header_text = f"Scanned: [bold]{stats['scanned']}[/] | Found: [bold green]{stats['found']}[/]"
        
        # Update panels
        layout["header"].update(Panel(header_text, title="Live Status", border_style="green"))
        layout["body"].update(self.table)
        
        return layout

    def add_row(self, result):
        """Adds a new found IP to the table."""
        self.table.add_row(
            result['ip'], 
            f"{result['latency']} ms", 
            result['timestamp']
        )
