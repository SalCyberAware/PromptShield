"""PromptShield command-line interface."""
import asyncio
import os
import sys
import uuid
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from . import __version__
from .attacks.library import AttackLibrary
from .engines.api_scanner import APIScanner, APIProvider, detect_provider
from .models import AttackCategory, AuthType, Severity, TargetConfig, TargetType
from .reporters.json_reporter import JSONReporter

load_dotenv()

console = Console()


def print_banner() -> None:
    banner = """
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘                                                               â•‘
â•‘    â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—     â•‘
â•‘    â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â•šâ•â•â–ˆâ–ˆâ•”â•â•â•     â•‘
â•‘    â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ–ˆâ–ˆâ•”â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•   â–ˆâ–ˆâ•‘        â•‘
â•‘    â–ˆâ–ˆâ•”â•â•â•â• â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•    â–ˆâ–ˆâ•‘        â•‘
â•‘    â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘ â•šâ•â• â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘        â–ˆâ–ˆâ•‘        â•‘
â•‘    â•šâ•â•     â•šâ•â•  â•šâ•â• â•šâ•â•â•â•â•â• â•šâ•â•     â•šâ•â•â•šâ•â•        â•šâ•â•        â•‘
â•‘                                                               â•‘
â•‘    SHIELD                                                     â•‘
â•‘                                                               â•‘
â•‘    Vulnerability Scanner for LLM Applications                 â•‘
â•‘    OWASP LLM Top 10  +  MITRE ATLAS  +  Custom Attacks        â•‘
â•‘                                                               â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
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


def resolve_api_key(target_url: str, explicit_key: str | None) -> str | None:
    if explicit_key:
        return explicit_key

    provider = detect_provider(target_url)

    if provider == APIProvider.ANTHROPIC:
        key = os.getenv("ANTHROPIC_API_KEY")
        if key:
            return key
    if provider == APIProvider.OPENAI:
        key = os.getenv("OPENAI_API_KEY")
        if key:
            return key

    return os.getenv("PROMPTSHIELD_API_KEY")


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit.")
@click.pass_context
def main(ctx: click.Context, version: bool) -> None:
    """PromptShield â€” Open-source LLM vulnerability scanner."""
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
)
@click.option(
    "--auth-type",
    type=click.Choice(["none", "bearer", "api_key"]),
    default="api_key",
)
@click.option("--api-key", default=None, help="API key. Prefer setting it in .env.")
@click.option("--categories", default=None, help="Comma-separated OWASP categories (e.g., LLM01,LLM06).")
@click.option("--rate-limit", default=10, help="Max requests per minute.")
@click.option("--timeout", default=30, help="Request timeout in seconds.")
@click.option("--output", "-o", default=None, help="Output file path. Format auto-detected from extension (.json or .html).")
@click.option("--dry-run", is_flag=True, help="Show what would be scanned without sending requests.")
@click.option("--verbose", "-v", is_flag=True, help="Print full request/response transcripts.")
@click.option("--no-transcripts", is_flag=True, help="Do not save transcripts in the output JSON.")
@click.option(
    "--use-ai-analyzer",
    is_flag=True,
    help="Run Claude AI analyzer in addition to pattern matching for higher accuracy.",
)
def scan(
    target: str,
    target_type: str,
    auth_type: str,
    api_key: str | None,
    categories: str | None,
    rate_limit: int,
    timeout: int,
    output: str | None,
    dry_run: bool,
    verbose: bool,
    no_transcripts: bool,
    use_ai_analyzer: bool,
) -> None:
    """Run a vulnerability scan against an LLM target."""
    print_banner()

    if target_type == "web":
        console.print("[red]Web scanning is coming in Phase 2. Use --type api for now.[/red]")
        sys.exit(1)

    library = AttackLibrary()
    selected_attacks = library.all()

    if categories:
        category_codes = [c.strip().upper() for c in categories.split(",")]
        selected_attacks = [a for a in selected_attacks if a.owasp_category in category_codes]

    if not selected_attacks:
        console.print("[red]No attacks matched your filters.[/red]")
        sys.exit(1)

    if not dry_run and auth_type != "none":
        resolved_key = resolve_api_key(target, api_key)
        if not resolved_key:
            console.print(
                "[red]No API key found.[/red] Set ANTHROPIC_API_KEY or OPENAI_API_KEY in .env, "
                "or pass --api-key (less secure)."
            )
            sys.exit(1)
        if api_key:
            key_source = "command line (less secure - use .env instead)"
        else:
            key_source = "environment / .env file"
    else:
        resolved_key = None
        key_source = "none"

    analyzers_str = "pattern_analyzer"
    if use_ai_analyzer:
        analyzers_str += " + claude_analyzer (AI)"

    panel_text = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Type:[/bold] {target_type}\n"
        f"[bold]Auth:[/bold] {auth_type}\n"
        f"[bold]Key source:[/bold] {key_source}\n"
        f"[bold]Rate limit:[/bold] {rate_limit} req/min\n"
        f"[bold]Categories:[/bold] {categories or 'all'}\n"
        f"[bold]Attacks loaded:[/bold] {len(selected_attacks)}\n"
        f"[bold]Analyzers:[/bold] {analyzers_str}\n"
        f"[bold]Save transcripts:[/bold] {'no' if no_transcripts else 'yes'}\n"
        f"[bold]Verbose:[/bold] {'yes' if verbose else 'no'}"
    )
    console.print(Panel(panel_text, title="Scan Configuration", border_style="cyan"))

    if dry_run:
        console.print("\n[yellow]DRY RUN â€” no requests will be sent.[/yellow]")
        table = Table(title="Attacks that would be sent", border_style="cyan")
        table.add_column("ID", style="cyan")
        table.add_column("OWASP")
        table.add_column("Name")
        table.add_column("Severity")
        for attack in selected_attacks[:25]:
            sev_color = SEVERITY_COLOR.get(attack.severity.value, "white")
            table.add_row(
                attack.id,
                attack.owasp_category,
                attack.name,
                f"[{sev_color}]{attack.severity.value}[/{sev_color}]",
            )
        console.print(table)
        if len(selected_attacks) > 25:
            console.print(f"[dim]...and {len(selected_attacks) - 25} more.[/dim]")
        return

    target_config = TargetConfig(
        url=target,
        target_type=TargetType.API,
        auth_type=AuthType(auth_type),
        auth_value=resolved_key,
        timeout=timeout,
        rate_limit=rate_limit,
    )

    scanner = APIScanner(target_config, selected_attacks)
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

    if use_ai_analyzer:
        estimated_cost = len(selected_attacks) * 0.003
        console.print(
            f"\n[yellow]AI analyzer enabled.[/yellow] Estimated cost: ~${estimated_cost:.3f} "
            f"({len(selected_attacks)} attacks Ã— ~$0.003 each)"
        )

    console.print(f"\n[cyan]Starting scan {scan_id}...[/cyan]\n")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )

    with progress:
        task = progress.add_task("[cyan]Scanning...", total=len(selected_attacks))

        def update_progress(current: int, total: int, attack):
            progress.update(task, completed=current, description=f"[cyan]{attack.id} - {attack.name[:40]}")

        scan_result = asyncio.run(
            scanner.run_scan(
                scan_id=scan_id,
                library_version="1.0.0",
                on_progress=update_progress,
                save_transcripts=not no_transcripts,
                use_ai_analyzer=use_ai_analyzer,
            )
        )

    console.print(f"\n[green]Scan complete![/green]")
    print_summary(scan_result)

    if verbose and scan_result.transcripts:
        print_transcripts(scan_result)

    if output:
        output_path = Path(output)
        ext = output_path.suffix.lower()
        if ext == ".html":
            from .reporters.html_reporter import HTMLReporter
            reporter = HTMLReporter()
        else:
            reporter = JSONReporter()
        saved = reporter.generate(scan_result, output_path)
        console.print(f"\n[green]Report saved to:[/green] {saved}")


def print_summary(scan_result) -> None:
    summary_table = Table(title="Scan Summary", border_style="cyan")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Scan ID", scan_result.scan_id)
    summary_table.add_row("Status", scan_result.status.value)
    summary_table.add_row("Target", scan_result.target.url)
    summary_table.add_row("Attacks run", f"{scan_result.attacks_run}/{scan_result.attacks_total}")
    summary_table.add_row("Findings", str(len(scan_result.findings)))
    summary_table.add_row("Transcripts saved", str(len(scan_result.transcripts)))
    summary_table.add_row("Analyzers used", ", ".join(scan_result.analyzers_used))

    if scan_result.started_at and scan_result.completed_at:
        duration = (scan_result.completed_at - scan_result.started_at).total_seconds()
        summary_table.add_row("Duration", f"{duration:.1f}s")

    console.print(summary_table)

    if scan_result.findings:
        console.print()
        findings_table = Table(title=f"Findings ({len(scan_result.findings)})", border_style="red")
        findings_table.add_column("Finding", style="cyan", no_wrap=True)
        findings_table.add_column("Severity")
        findings_table.add_column("OWASP")
        findings_table.add_column("Title")
        findings_table.add_column("Confidence")
        findings_table.add_column("Analyzers", style="dim")

        for finding in scan_result.findings:
            sev_color = SEVERITY_COLOR.get(finding.severity.value, "white")
            agreed = finding.evidence.get("analyzers_agreed", False)
            agreement_marker = "âœ“ agreed" if agreed and len(finding.analyzer_verdicts) > 1 else f"{len(finding.analyzer_verdicts)} run"
            findings_table.add_row(
                finding.finding_id,
                f"[{sev_color}]{finding.severity.value}[/{sev_color}]",
                finding.evidence.get("owasp_category", "-"),
                finding.title[:50],
                f"{finding.confidence_score*100:.0f}%",
                agreement_marker,
            )

        console.print(findings_table)
    else:
        console.print("\n[green]No findings detected.[/green] [dim](use --verbose to see what the model said)[/dim]")


def print_transcripts(scan_result) -> None:
    """Print full request/response transcripts for inspection."""
    console.print("\n[bold cyan]=== Transcripts ===[/bold cyan]\n")
    for transcript in scan_result.transcripts:
        sev_color = SEVERITY_COLOR.get(transcript.severity.value, "white")
        marker = "[red]FINDING[/red]" if transcript.became_finding else "[green]CLEAN[/green]"
        analyzers_str = ", ".join(transcript.analyzers_run) if transcript.analyzers_run else "none"
        header = (
            f"[bold]{transcript.attack_id}[/bold] Â· {transcript.owasp_category} Â· "
            f"[{sev_color}]{transcript.severity.value}[/{sev_color}] Â· {marker} Â· "
            f"{transcript.duration_seconds}s Â· analyzers: {analyzers_str}"
        )
        console.print(header)
        console.print(f"[bold]Attack:[/bold] {transcript.attack_name}")
        console.print(Panel(transcript.prompt, title="prompt sent", border_style="dim", style="yellow"))
        truncated_note = " [dim](truncated)[/dim]" if transcript.response_truncated else ""
        console.print(Panel(transcript.response, title=f"response received{truncated_note}", border_style="dim"))
        console.print()


@main.group()
def library() -> None:
    """Manage the attack library."""


@library.command("list")
@click.option("--category", default=None)
@click.option("--severity", default=None)
@click.option("--tag", default=None)
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
        console.print(f"  - {indicator}")

    console.print("\n[bold cyan]Remediation:[/bold cyan]")
    console.print(f"  {attack.remediation}")

    if attack.references:
        console.print("\n[bold cyan]References:[/bold cyan]")
        for ref in attack.references:
            console.print(f"  - {ref}")


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
    console.print("[yellow]Library update functionality coming soon.[/yellow]")


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
    anthropic_set = "yes" if os.getenv("ANTHROPIC_API_KEY") else "no"
    openai_set = "yes" if os.getenv("OPENAI_API_KEY") else "no"
    table.add_row("ANTHROPIC_API_KEY in env", anthropic_set)
    table.add_row("OPENAI_API_KEY in env", openai_set)
    table.add_row("AI analyzer available", "yes" if anthropic_set == "yes" else "no (needs ANTHROPIC_API_KEY)")
    table.add_row("GitHub", "https://github.com/SalCyberAware/PromptShield")
    table.add_row("License", "MIT")
    console.print(table)


if __name__ == "__main__":
    main()
