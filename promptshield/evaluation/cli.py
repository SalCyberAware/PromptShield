"""``promptshield eval`` — run the verdict benchmark and report the score."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .baseline import BaselineError, compare_to_baseline, load_baseline, write_baseline
from .benchmark import load_benchmark
from .runner import JUDGES, run_benchmark_sync

console = Console()


def _print_report(report: Any, show_agreements: bool) -> None:
    metrics = report.metrics

    summary = Table(show_header=True, header_style="bold")
    summary.add_column("Verdict")
    summary.add_column("Support", justify="right")
    summary.add_column("Predicted", justify="right")
    summary.add_column("Precision", justify="right")
    summary.add_column("Recall", justify="right")
    summary.add_column("F1", justify="right")
    for entry in metrics.per_class:
        summary.add_row(
            entry.verdict,
            str(entry.support),
            str(entry.predicted),
            f"{entry.precision:.3f}",
            f"{entry.recall:.3f}",
            f"{entry.f1:.3f}",
        )

    console.print(
        Panel(
            f"[bold]{metrics.correct}/{metrics.total}[/bold] correct  ·  "
            f"accuracy [bold]{metrics.accuracy:.3f}[/bold]\n"
            f"judge: [cyan]{report.judge}[/cyan]"
            + (f" ([dim]{report.judge_model}[/dim])" if report.judge_model else ""),
            title="Benchmark result",
        )
    )
    console.print(summary)

    disagreements = report.disagreements
    if disagreements:
        console.print(
            f"\n[bold red]{len(disagreements)} disagreement(s)[/bold red] "
            "— judge reasoning beside the human rationale:\n"
        )
    for result in disagreements:
        case = result.case
        console.print(
            Panel(
                f"[bold]labeled[/bold]   [green]{case.verdict}[/green]"
                f"    [bold]judged[/bold] [red]{result.predicted}[/red]"
                + (
                    f"    [dim]confidence {result.judge_confidence:.2f}[/dim]"
                    if result.judge_confidence is not None
                    else ""
                )
                + f"\n\n[bold]human rationale[/bold]\n{case.rationale}"
                + f"\n\n[bold]judge reasoning[/bold]\n{result.judge_reasoning or '(none)'}",
                title=f"{case.id} · {case.attack_id} · {case.attack_name}",
                border_style="red",
            )
        )

    if show_agreements:
        for result in report.results:
            if result.agrees:
                console.print(
                    f"[green]✓[/green] {result.case.id} {result.case.verdict}"
                )


@click.group()
def evaluate() -> None:
    """Score analyzer verdicts against the labeled benchmark."""


@evaluate.command("run")
@click.option(
    "--benchmark", "benchmark_path", type=click.Path(path_type=Path),
    help="Benchmark file (defaults to the packaged one).",
)
@click.option(
    "--judge", "judge_name", default="claude",
    type=click.Choice(sorted([*JUDGES, "none"])),
    help="Which judge to score. 'none' scores the pattern floor alone.",
)
@click.option(
    "--include-unreviewed", is_flag=True,
    help="Also score cases whose labels nobody has confirmed yet. Off by default: "
         "an unreviewed label is a candidate, not ground truth.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.option("--show-agreements", is_flag=True, help="Also list the cases that matched.")
@click.option(
    "--check-baseline", is_flag=True,
    help="Fail if accuracy fell below the recorded baseline.",
)
@click.option(
    "--write-baseline", "should_write_baseline", is_flag=True,
    help="Record this run's accuracy as the new baseline.",
)
def evaluate_run(
    benchmark_path: Path | None,
    judge_name: str,
    include_unreviewed: bool,
    as_json: bool,
    show_agreements: bool,
    check_baseline: bool,
    should_write_baseline: bool,
) -> None:
    """Run every case through the analyzer pipeline and score the verdicts."""
    benchmark = load_benchmark(benchmark_path)

    scored = benchmark.cases if include_unreviewed else benchmark.reviewed()
    if not scored:
        console.print(
            "[yellow]No reviewed cases to score.[/yellow] The benchmark has "
            f"{len(benchmark.unreviewed())} unreviewed case(s); confirm some labels, "
            "or pass --include-unreviewed to score against candidates."
        )
        raise SystemExit(0)

    report = run_benchmark_sync(
        benchmark, judge_name=judge_name, include_unreviewed=include_unreviewed
    )

    if as_json:
        click.echo(
            json.dumps(
                {
                    "provenance": report.provenance,
                    "accuracy": report.metrics.accuracy,
                    "correct": report.metrics.correct,
                    "total": report.metrics.total,
                    "per_class": [
                        {
                            "verdict": entry.verdict,
                            "support": entry.support,
                            "predicted": entry.predicted,
                            "precision": entry.precision,
                            "recall": entry.recall,
                            "f1": entry.f1,
                        }
                        for entry in report.metrics.per_class
                    ],
                    "confusion": report.metrics.confusion,
                    "disagreements": [
                        {
                            "case_id": result.case.id,
                            "attack_id": result.case.attack_id,
                            "labeled": result.case.verdict,
                            "predicted": result.predicted,
                            "human_rationale": result.case.rationale,
                            "judge_reasoning": result.judge_reasoning,
                            "judge_confidence": result.judge_confidence,
                        }
                        for result in report.disagreements
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_report(report, show_agreements)

    if should_write_baseline:
        path = write_baseline(report)
        console.print(f"\n[green]Baseline written[/green] → {path}")

    if check_baseline:
        try:
            baseline = load_baseline()
        except BaselineError as exc:
            console.print(f"[red]{exc}[/red]")
            raise SystemExit(1) from exc
        verdict = compare_to_baseline(report, baseline)
        console.print("\n" + verdict.message)
        if not verdict.passed:
            raise SystemExit(1)


@evaluate.command("cases")
@click.option(
    "--benchmark", "benchmark_path", type=click.Path(path_type=Path),
    help="Benchmark file (defaults to the packaged one).",
)
@click.option("--unreviewed-only", is_flag=True, help="Only cases awaiting review.")
def evaluate_cases(benchmark_path: Path | None, unreviewed_only: bool) -> None:
    """List the benchmark's cases and their review state."""
    benchmark = load_benchmark(benchmark_path)
    cases = benchmark.unreviewed() if unreviewed_only else benchmark.cases

    table = Table(show_header=True, header_style="bold")
    table.add_column("Case")
    table.add_column("Attack")
    table.add_column("Verdict")
    table.add_column("Review")
    table.add_column("By")
    for case in cases:
        table.add_row(
            case.id,
            case.attack_id,
            case.verdict,
            ("[green]REVIEWED[/green]" if case.reviewed else "[yellow]UNREVIEWED[/yellow]"),
            case.proposed_by,
        )
    console.print(table)
    console.print(
        f"\n{len(benchmark)} case(s): "
        f"{len(benchmark.reviewed())} reviewed, {len(benchmark.unreviewed())} unreviewed "
        f"· benchmark v{benchmark.version}"
    )
