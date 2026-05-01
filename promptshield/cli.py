"""PromptShield command-line interface."""
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .attacks.library import AttackLibrary
from .models import AttackCategory, Severity

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


SEVERITY_COLOR = {
    "info": "blue",
    "low": "green",
    "medium": "yellow",
    "high": "orange3",
    "critical": "red",
}


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

    library = AttackLibrary()
    selected_attacks = library.all()

    if categories:
        category_codes = [c.strip().upper() for c in categories.split(",")]
        selected_attacks = [a for a in selected_attacks if a.owasp_category in category_codes]

    panel_text = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Type:[/bold] {target_type}\n"
        f"[bold]Auth:[/bold] {auth_type}\n"
        f"[bold]Categories:[/bold] {categories or 'all'}\n"
        f"[bold]Attacks loaded:[/bold] {len(selected_attacks)}"
    )
    console.print(Panel(panel_text, title="Scan Configuration", border_style="cyan"))

    console.print("\n[yellow]Scanner engine implementation coming next.[/yellow]")
    console.print("[dim]Use 'promptshield library list' to see all loaded attacks.[/dim]\n")


@main.group()
def library() -> None:
    """Manage the attack library."""


@library.command("list")
@click.option("--category", default=None, help="Filter by OWASP category (e.g., LLM01).")
@click.option("--severity", default=None, help="Filter by severity (low, medium, high, critical).")
@click.option("--tag", default=None, help="Filter by tag.")
def library_list(category: str | None, severity: str | None, tag: str | None) -> None:
    """List available attacks in the library."""
    lib = AttackLibrary()
    attacks = lib.all()

    if category:
        attacks = [a for a in attacks if a.owasp_category.upper() == category.upper()]
    if severity:
        attacks = [a for a in attacks if a.severity.value == severity.lower()]
    if tag:
        attacks = [a for a in attacks if tag.lower() in [t.lower() for t in a.tags]]

    table = Table(title=f"PromptShield Attack Library ({len(attacks)} attacks)", border_style="cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("OWASP", style="magenta")
    table.add_column("Name", style="white")
    table.add_column("Severity")
    table.add_column("Tags", style="dim")

    for attack in attacks:
        sev_color = SEVERITY_COLOR.get(attack.severity.value, "white")
        tag_str = ", ".join(attack.tags[:3])
        table.add_row(
            attack.id,
            attack.owasp_category,
            attack.name,
            f"[{sev_color}]{attack.severity.value}[/{sev_color}]",
            tag_str,
        )

    console.print(table)


@library.command("show")
@click.argument("attack_id")
def library_show(attack_id: str) -> None:
    """Show full details for a specific attack."""
    lib = AttackLibrary()
    attack = lib.get(attack_id)

    if not attack:
        console.print(f"[red]Attack not found:[/red] {attack_id}")
        sys.exit(1)

    sev_color = SEVERITY_COLOR.get(attack.severity.value, "white")

    table = Table(border_style="cyan", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("ID", attack.id)
    table.add_row("Name", attack.name)
    table.add_row("Category", f"{attack.owasp_category} - {attack.category.value}")
    if attack.mitre_atlas:
        table.add_row("MITRE ATLAS", attack.mitre_atlas)
    table.add_row("Severity", f"[{sev_color}]{attack.severity.value}[/{sev_color}]")
    table.add_row("Description", attack.description)
    table.add_row("Tags", ", ".join(attack.tags))

    console.print(Panel(table, title=f"Attack Details: {attack.id}", border_style="cyan"))

    console.print("\n[bold cyan]Prompt:[/bold cyan]")
    console.print(Panel(attack.prompt, border_style="dim"))

    console.print("\n[bold cyan]Expected Indicators:[/bold cyan]")
    for indicator in attack.expected_indicators:
        console.print(f"  • {indicator}")

    console.print("\n[bold cyan]Remediation:[/bold cyan]")
    console.print(f"  {attack.remediation}")

    if attack.references:
        console.print("\n[bold cyan]References:[/bold cyan]")
        for ref in attack.references:
            console.print(f"  • {ref}")


@library.command("stats")
def library_stats() -> None:
    """Show statistics about the attack library."""
    lib = AttackLibrary()
    stats = lib.stats()

    table = Table(title="Attack Library Statistics", border_style="cyan", show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="white", justify="right")

    table.add_row("Total attacks", str(stats.get("total", 0)))
    table.add_row("", "")

    for category in AttackCategory:
        count = stats.get(category.value, 0)
        if count > 0:
            table.add_row(f"  {category.value}", str(count))

    table.add_row("", "")

    for severity in Severity:
        count = stats.get(f"severity_{severity.value}", 0)
        if count > 0:
            sev_color = SEVERITY_COLOR.get(severity.value, "white")
            table.add_row(f"  [{sev_color}]{severity.value}[/{sev_color}]", str(count))

    console.print(table)


@library.command("update")
def library_update() -> None:
    """Update the attack library from configured sources."""
    console.print("[yellow]Library update functionality coming in Phase 1.[/yellow]")


@main.command()
def info() -> None:
    """Show PromptShield system information."""
    print_banner()
    lib = AttackLibrary()

    table = Table(border_style="cyan", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Version", __version__)
    table.add_row("Python required", ">=3.11")
    table.add_row("Attacks in library", str(len(lib)))
    table.add_row("GitHub", "https://github.com/SalCyberAware/PromptShield")
    table.add_row("License", "MIT")
    console.print(table)


if __name__ == "__main__":
    main()
