"""Attack engine for executing prompt injection payloads."""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from promptscan.analyzer import ResponseAnalyzer, VulnerabilityMatch
from promptscan.client import HTTPClient
from promptscan.config import DEFAULT_PAYLOAD_DIR, ScanConfig

console = Console()


class AttackEngine:
    """Engine for executing prompt injection attacks."""

    def __init__(self, config: ScanConfig) -> None:
        """Initialize the attack engine.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.client = HTTPClient(config)
        self.analyzer = ResponseAnalyzer()
        self.payload_dir = config.payload_dir or DEFAULT_PAYLOAD_DIR

    def load_payloads(self) -> Dict[str, List[str]]:
        """Load attack payloads from files.
        
        Returns:
            Dictionary mapping category names to lists of payloads
        """
        payloads: Dict[str, List[str]] = {}

        if not self.payload_dir.exists():
            console.print(f"[yellow]Warning: Payload directory not found: {self.payload_dir}[/yellow]")
            return payloads

        # Load payloads from each category file
        for payload_file in self.payload_dir.glob("*.txt"):
            category = payload_file.stem.replace("_", " ").title()
            
            try:
                with open(payload_file, "r", encoding="utf-8") as f:
                    file_payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    if file_payloads:
                        payloads[category] = file_payloads
                        if self.config.verbose:
                            console.print(f"[green]Loaded {len(file_payloads)} payloads from {category}[/green]")
            except Exception as e:
                console.print(f"[red]Error loading {payload_file}: {str(e)}[/red]")

        return payloads

    async def run_scan(self) -> Tuple[List[VulnerabilityMatch], Dict[str, Any]]:
        """Run the complete security scan.
        
        Returns:
            Tuple of (vulnerabilities list, scan metadata)
        """
        console.print("\n[bold cyan]PromptScan Security Assessment[/bold cyan]")
        console.print(f"[cyan]Target:[/cyan] {self.config.target_url}\n")

        # Test connection
        console.print("[yellow]Testing connection...[/yellow]")
        if not await self.client.test_connection():
            console.print("[red]✗ Connection failed. Please check the target URL and authentication.[/red]")
            return [], {"error": "Connection failed"}

        console.print("[green]✓ Connection successful[/green]\n")

        # Load payloads
        console.print("[yellow]Loading attack payloads...[/yellow]")
        payloads = self.load_payloads()
        
        if not payloads:
            console.print("[red]✗ No payloads found. Please check the payload directory.[/red]")
            return [], {"error": "No payloads found"}

        total_payloads = sum(len(p) for p in payloads.values())
        console.print(f"[green]✓ Loaded {total_payloads} payloads across {len(payloads)} categories[/green]\n")

        # Execute attacks
        console.print("[bold yellow]Executing security tests...[/bold yellow]")
        all_vulnerabilities: List[VulnerabilityMatch] = []
        flagged_payloads = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Testing payloads...", total=total_payloads)

            for category, category_payloads in payloads.items():
                for payload in category_payloads:
                    # Send payload
                    response_data = await self.client.send_payload(payload)
                    
                    # Analyze response
                    vulnerabilities = self.analyzer.analyze_response(
                        response_data, payload, category
                    )
                    
                    all_vulnerabilities.extend(vulnerabilities)
                    if vulnerabilities:
                        flagged_payloads += 1

                    progress.update(task, advance=1)
                    
                    # Small delay to avoid overwhelming the API
                    await asyncio.sleep(0.1)

        # Prepare metadata
        metadata = {
            "total_payloads": total_payloads,
            "categories_tested": len(payloads),
            "vulnerabilities_found": len(all_vulnerabilities),
            # Payloads that produced at least one finding vs. those that did not.
            # (A single payload can trigger multiple findings, so these are
            # counted per-payload to stay consistent with total_payloads.)
            "successful_attacks": flagged_payloads,
            "failed_attacks": total_payloads - flagged_payloads,
        }

        console.print(f"\n[green]✓ Scan complete[/green]")
        console.print(f"[cyan]Vulnerabilities found:[/cyan] {len(all_vulnerabilities)}")

        return all_vulnerabilities, metadata

    def get_payload_categories(self) -> List[str]:
        """Get list of available payload categories.
        
        Returns:
            List of category names
        """
        if not self.payload_dir.exists():
            return []

        categories = []
        for payload_file in self.payload_dir.glob("*.txt"):
            category = payload_file.stem.replace("_", " ").title()
            categories.append(category)

        return sorted(categories)
