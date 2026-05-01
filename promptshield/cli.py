"""PromptShield command-line interface."""
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__

console = Console()


def print_banner() -> None:
    """Print the PromptShield banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ██████╗  ██████╗ ███╗   ███╗██████╗ ████████╗     ║
║    ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝     ║
║    ██████╔╝██████╔╝██║   ██║██╔████╔██║██████╔╝   ██║        ║
║    ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔═══╝    ██║        ║
║    ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║        ██║        ║
║    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝        ╚═╝        ║
║                                                               ║
║    SHIELD                                                     ║
║                                                               ║
║    Vulnerability Scanner for LLM Applications                 ║
║    OWASP LLM Top 10  +  MITRE ATLAS  +  Custom Attacks        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")
    console.print(f"  Version {__version__}\n", style="dim")


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit.")
@click.pass_context
def main(ctx: click.Context, version: bool) -> None:
    """PromptShield — Open-source LLM vulnerability scanner."""
    if version:
        click.echo(f"PromptShield v{__version__}")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@main.command()
@click.option("--target", "-t", required=True, help="Target URL to scan.")
@click.option(
    "--type",
    "target_type",
    type=click.Choice(["api", "web"]),
    default="api",
    help="Target type: api or web.",
)
@click.option("--auth-type", default="none", help="Authentication type.")
@click.option("--api-key", default=None, help="API key for authentication.")
@click.option("--categories", default=None, help="Comma-separated OWASP categories (e.g., LLM01,LLM06).")
@click.option("--output", "-o", default=None, help="Output file for the report (JSON).")
def scan(
    target: str,
    target_type: str,
    auth_type: str,
    api_key: str | None,
    categories: str | None,
    output: str | None,
) -> None:
    """Run a vulnerability scan against an LLM target."""
    print_banner()

    panel_text = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Type:[/bold] {target_type}\n"
        f"[bold]Auth:[/bold] {auth_type}\n"
        f"[bold]Categories:[/bold] {categories or 'all'}"
    )
    console.print(Panel(panel_text, title="Scan Configuration", border_style="cyan"))

    console.print("\n[yellow]Phase 1 implementation in progress.[/yellow]")
    console.print("[dim]Scanner engine coming soon.[/dim]\n")


@main.group()
def library() -> None:
    """Manage the attack library."""


@library.command("list")
@click.option("--category", default=None, help="Filter by OWASP category.")
def library_list(category: str | None) -> None:
    """List available attacks in the library."""
    table = Table(title="PromptShield Attack Library", border_style="cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Name", style="white")
    table.add_column("Severity", style="yellow")

    table.add_row(
        "PS-LLM01-001",
        "LLM01",
        "Direct instruction override",
        "high",
    )
    table.add_row(
        "PS-LLM06-001",
        "LLM06",
        "System prompt extraction",
        "medium",
    )

    console.print(table)
    console.print("\n[dim]Library will expand to 50+ attacks in Phase 1.[/dim]")


@library.command("update")
def library_update() -> None:
    """Update the attack library from configured sources."""
    console.print("[yellow]Library update functionality coming in Phase 1.[/yellow]")


@main.command()
def info() -> None:
    """Show PromptShield system information."""
    print_banner()
    table = Table(border_style="cyan", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Version", __version__)
    table.add_row("Python required", ">=3.11")
    table.add_row("GitHub", "https://github.com/SalCyberAware/PromptShield")
    table.add_row("License", "MIT")
    console.print(table)


if __name__ == "__main__":
    main()
