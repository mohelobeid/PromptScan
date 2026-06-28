"""Command-line interface for PromptScan."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from promptscan.config import ScanConfig
from promptscan.engine import AttackEngine
from promptscan.reporter import ReportGenerator

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="PromptScan")
def cli() -> None:
    """PromptScan - Professional LLM Security Assessment Tool
    
    A CLI tool for testing chatbot and LLM APIs against prompt injection vulnerabilities.
    """
    pass


@cli.command()
@click.argument("target_url")
@click.option(
    "--api-key",
    "-k",
    help="API key for authentication (X-API-Key header)",
    default=None,
)
@click.option(
    "--bearer-token",
    "-b",
    help="Bearer token for authentication (Authorization header)",
    default=None,
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=30,
    help="Request timeout in seconds (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["console", "json", "html"], case_sensitive=False),
    default="console",
    help="Output format (default: console)",
)
@click.option(
    "--report",
    "-r",
    type=click.Path(),
    help="Output file path for JSON/HTML reports",
    default=None,
)
@click.option(
    "--payloads",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    help="Custom payload directory",
    default=None,
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def test(
    target_url: str,
    api_key: Optional[str],
    bearer_token: Optional[str],
    timeout: int,
    output: str,
    report: Optional[str],
    payloads: Optional[str],
    verbose: bool,
) -> None:
    """Test a target API for prompt injection vulnerabilities.
    
    TARGET_URL: The API endpoint to test (e.g., https://api.example.com/chat)
    
    Examples:
    
        # Basic scan
        promptscan test https://api.example.com/chat
        
        # With API key authentication
        promptscan test https://api.example.com/chat --api-key YOUR_KEY
        
        # Generate JSON report
        promptscan test https://api.example.com/chat -o json -r report.json
        
        # Generate HTML report
        promptscan test https://api.example.com/chat -o html -r report.html
    """
    try:
        # Validate output file requirement
        if output in ["json", "html"] and not report:
            console.print("[red]Error: --report is required when using JSON or HTML output[/red]")
            sys.exit(1)

        # Create configuration
        config = ScanConfig(
            target_url=target_url,
            api_key=api_key,
            bearer_token=bearer_token,
            timeout=timeout,
            output_format=output,
            output_file=Path(report) if report else None,
            payload_dir=Path(payloads) if payloads else None,
            verbose=verbose,
        )

        # Run the scan
        engine = AttackEngine(config)
        vulnerabilities, metadata = asyncio.run(engine.run_scan())

        # If the scan could not run (e.g. unreachable target or no payloads),
        # do NOT emit a "clean" report — that would be a misleading false
        # negative for a security tool. Surface the error and exit non-zero.
        if metadata.get("error"):
            console.print(
                f"[red]Scan did not complete: {metadata['error']}[/red]"
            )
            sys.exit(2)

        # Generate report
        reporter = ReportGenerator()

        if output == "console":
            reporter.generate_console_report(vulnerabilities, metadata, target_url)
        elif output == "json":
            reporter.generate_json_report(
                vulnerabilities, metadata, target_url, config.output_file  # type: ignore
            )
        elif output == "html":
            reporter.generate_html_report(
                vulnerabilities, metadata, target_url, config.output_file  # type: ignore
            )

        # Exit with appropriate code
        if vulnerabilities:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command()
def list_payloads() -> None:
    """List available payload categories."""
    from promptscan.config import DEFAULT_PAYLOAD_DIR

    console.print("\n[bold cyan]Available Payload Categories:[/bold cyan]\n")

    if not DEFAULT_PAYLOAD_DIR.exists():
        console.print("[yellow]No payload directory found. Please check installation.[/yellow]")
        return

    categories = []
    for payload_file in DEFAULT_PAYLOAD_DIR.glob("*.txt"):
        category = payload_file.stem.replace("_", " ").title()
        
        # Count payloads
        try:
            with open(payload_file, "r", encoding="utf-8") as f:
                count = sum(
                    1 for line in f
                    if line.strip() and not line.strip().startswith("#")
                )
            categories.append((category, count, payload_file.name))
        except Exception:
            continue

    if not categories:
        console.print("[yellow]No payload files found.[/yellow]")
        return

    for category, count, filename in sorted(categories):
        console.print(f"  • [cyan]{category}[/cyan]: {count} payloads ({filename})")

    console.print(f"\n[green]Total: {len(categories)} categories[/green]\n")


@cli.command()
def info() -> None:
    """Display information about PromptScan."""
    console.print("\n[bold cyan]PromptScan v1.0.0[/bold cyan]")
    console.print("[cyan]Professional LLM Security Assessment Tool[/cyan]\n")
    
    console.print("[bold]Description:[/bold]")
    console.print("  A CLI tool for testing chatbot and LLM APIs against prompt injection")
    console.print("  vulnerabilities. Designed for security professionals and developers.\n")
    
    console.print("[bold]Features:[/bold]")
    console.print("  • 36 high-quality attack payloads across 6 categories")
    console.print("  • Intelligent response analysis and pattern matching")
    console.print("  • Risk scoring algorithm (0-10 scale)")
    console.print("  • Multiple output formats (console, JSON, HTML)")
    console.print("  • API key and Bearer token authentication support")
    console.print("  • Detailed vulnerability reports\n")
    
    console.print("[bold]Usage:[/bold]")
    console.print("  promptscan test <target_url> [options]")
    console.print("  promptscan list-payloads")
    console.print("  promptscan info\n")
    
    console.print("[bold]Documentation:[/bold]")
    console.print("  https://github.com/mohelobeid/promptscan\n")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
