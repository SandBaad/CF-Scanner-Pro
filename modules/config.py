import json
import os
import time
from rich import print as rprint
from rich.panel import Panel
import questionary

class ConfigManager:
    """
    Handles configuration loading, validation, and user interaction.
    Manages the 'config.json' file and the interactive setup wizard.
    """
    CONFIG_FILE = "config.json"

    @staticmethod
    def load_config():
        """
        Loads configuration logic:
        1. Checks if a config file exists.
        2. Asks the user whether to load it or start a new scan.
        3. Falls back to the wizard if no file exists or user declines.
        """
        
        # Check if the configuration file exists in the root directory
        if os.path.exists(ConfigManager.CONFIG_FILE):
            # Prompt the user: Use saved config or create a new one?
            use_saved = questionary.confirm(
                "Found saved configuration. Use it?", 
                default=True,
                qmark="📂"
            ).ask()

            if use_saved:
                try:
                    with open(ConfigManager.CONFIG_FILE, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        rprint(f"[green]✓ Configuration loaded successfully[/green]")
                        time.sleep(0.5)
                        return config
                except Exception as e:
                    rprint(f"[red]⚠ Error reading config file: {e}[/red]")
            
        # If file is missing or user chose 'No', launch the setup wizard
        return ConfigManager.run_wizard()

    @staticmethod
    def run_wizard():
        """
        Runs the interactive terminal wizard to gather scan settings.
        Returns a dictionary containing the user's preferences.
        """
        
        # Display the application banner
        rprint(Panel.fit(
            "[bold cyan]CF-SCANNER PRO[/bold cyan]\n[dim]Modular Edition[/dim]",
            border_style="blue"
        ))

        # Step 1: Get Target Domain (SNI)
        domain = questionary.text(
            "Target Domain (SNI):", 
            default="gooooosaaaaale.heyvoon.shop"
        ).ask()
        
        # Step 2: Select Scan Mode
        mode = questionary.select(
            "Scan Mode:",
            choices=["Secure (Recommended)", "Aggressive (High Speed)", "Custom"]
        ).ask()

        # Set parameters based on selected mode
        if mode.startswith("Secure"):
            workers, timeout, randomize = 20, 2.0, True
        elif mode.startswith("Aggressive"):
            workers, timeout, randomize = 100, 1.0, True
        else:
            # Custom configuration input
            workers = int(questionary.text("Max Workers:", default="50").ask())
            timeout = float(questionary.text("Timeout (sec):", default="1.5").ask())
            randomize = questionary.confirm("Randomize IPs?", default=True).ask()

        # Construct configuration dictionary
        config = {
            "domain": domain,
            "port": 443,
            "workers": workers,
            "timeout": timeout,
            "randomize": randomize,
            "subnets_file": "subnets.txt"
        }

        # Step 3: Option to save configuration for future use
        if questionary.confirm("Save as default config?", default=True).ask():
            with open(ConfigManager.CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
                rprint("[dim]Configuration saved to config.json[/dim]")

        return config
