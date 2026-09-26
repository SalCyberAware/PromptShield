"""``promptshield eval`` — run the verdict benchmark and report the score."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..env import load_env_files
from ..models import Attack, AttackCategory, Severity
from .baseline import BaselineError, compare_to_baseline, load_baseline, write_baseline
from .benchmark import (
    BenchmarkCase,
    BenchmarkError,
    dump_benchmark,
    is_default_benchmark,
    load_benchmark,
)
from .prompts import resolve_prompt
from .review import (
    ReviewError,
    apply_decision,
    change_case,
    confirm_case,
    default_reviewer,
    queue_summary,
    review_queue,
)
from .runner import JUDGE_FALLBACKS, JUDGES, JudgeUnavailableError, run_benchmark_sync

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
                f"    [bold]predicted[/bold] [red]{result.predicted}[/red]"
                + (
                    f"    [bold]judge said[/bold] {result.judge_verdict}"
                    f" [dim]({result.judge_name})[/dim]"
                    if result.judge_verdict
                    else "    [bold]judge said[/bold] nothing"
                )
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


def _case_json(result: Any) -> dict[str, Any]:
    return {
        "case_id": result.case.id,
        "attack_id": result.case.attack_id,
        "labeled": result.case.verdict,
        "predicted": result.predicted,
        "judge": result.judge_name,
        "judge_verdict": result.judge_verdict,
        "judge_confidence": result.judge_confidence,
        "judge_errored": result.judge_errored,
    }


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
    gated = is_default_benchmark(benchmark_path)
    if not gated and (check_baseline or should_write_baseline):
        # Refused before a single judge call: the baseline describes the
        # packaged benchmark, and a held-out file exists to be reported
        # beside it, never to become (or be compared as) the gate.
        raise click.UsageError(
            f"--check-baseline and --write-baseline only apply to the packaged "
            f"benchmark; {benchmark_path} is scored and reported, never recorded "
            "as the gate."
        )
    benchmark = load_benchmark(benchmark_path)

    scored = benchmark.cases if include_unreviewed else benchmark.reviewed()
    if not scored:
        console.print(
            "[yellow]No reviewed cases to score.[/yellow] The benchmark has "
            f"{len(benchmark.unreviewed())} unreviewed case(s); confirm some labels, "
            "or pass --include-unreviewed to score against candidates."
        )
        raise SystemExit(0)

    try:
        report = run_benchmark_sync(
            benchmark, judge_name=judge_name, include_unreviewed=include_unreviewed
        )
    except JudgeUnavailableError as exc:
        console.print(f"[red]Run stopped: {exc}[/red]")
        console.print(
            "No score is reported. A run the primary judge could not finish would "
            "describe a different measurement for every case it missed."
        )
        raise SystemExit(2) from exc

    if as_json:
        click.echo(
            json.dumps(
                {
                    "benchmark_file": str(benchmark.path),
                    "gated": gated,
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
                    # Every case, with what the judge itself said, so a
                    # disagreement never has to be inferred from the status.
                    "cases": [_case_json(result) for result in report.results],
                    "disagreements": [
                        {
                            **_case_json(result),
                            "human_rationale": result.case.rationale,
                            "judge_reasoning": result.judge_reasoning,
                        }
                        for result in report.disagreements
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_report(report, show_agreements)
        if not gated:
            console.print(
                f"\n[cyan]{benchmark.path}[/cyan] (v{benchmark.version}) is not the "
                "packaged benchmark: reported only, never recorded as the baseline."
            )

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


def _scrub(text: str) -> str:
    """Remove any configured key value from ``text`` before it is printed."""
    for name, value in os.environ.items():
        if value and len(value) >= 8 and ("KEY" in name or "TOKEN" in name):
            text = text.replace(value, "***")
    return text


@evaluate.command("preflight")
@click.option(
    "--judge", "judge_name", default="claude",
    type=click.Choice(sorted(JUDGES)),
    help="The primary judge whose chain to check.",
)
@click.option(
    "--benchmark", "benchmark_path", type=click.Path(path_type=Path),
    help="Also check this benchmark file loads and every case resolves to its "
         "system prompt (defaults to the packaged one).",
)
def evaluate_preflight(judge_name: str, benchmark_path: Path | None) -> None:
    """Check each judge in the chain can be paid for, before a billed run.

    One minimal real call per judge -- the same ``analyze`` path a scoring run
    uses, on a harmless question -- so a run does not discover an unfunded key
    or a missing fallback halfway through. Reports which fallbacks are not
    configured at all, which is what hid a missing Gemini key from a whole live
    run. Key values are never printed.

    The benchmark is checked first, and costs nothing: a file that does not
    parse, or a case whose prompt cannot be resolved (so the prompt-leak floor
    would run blind), fails here rather than after the judge has been paid.
    """
    try:
        benchmark = load_benchmark(benchmark_path)
    except BenchmarkError as exc:
        console.print(f"[red]benchmark: {exc}[/red]")
        raise SystemExit(2) from exc
    unresolved = sorted(
        {str(case.source.get("prompt") or "<none>") for case in benchmark.cases
         if resolve_prompt(str(case.source.get("prompt") or "")) is None}
    )
    console.print(
        f"benchmark: {benchmark.path} (v{benchmark.version}) · {len(benchmark)} case(s), "
        f"{len(benchmark.reviewed())} reviewed · "
        + ("gated by the baseline" if is_default_benchmark(benchmark_path)
           else "held-out: reported, never gated")
    )
    if unresolved:
        console.print(f"[red]benchmark: unknown prompt key(s) {', '.join(unresolved)}[/red]")
        raise SystemExit(2)

    probe = Attack(
        id="PREFLIGHT",
        category=AttackCategory.CUSTOM,
        owasp_category="CUSTOM",
        name="Pre-flight probe",
        description="Asks a harmless arithmetic question.",
        severity=Severity.INFO,
        prompt="What is 2 + 2?",
        remediation="None needed.",
    )
    loaded = load_env_files()
    console.print(
        "env files: " + (", ".join(str(path) for path in loaded) or "[yellow]none found[/yellow]")
    )

    primary_ok = False
    for index, name in enumerate((judge_name, *JUDGE_FALLBACKS.get(judge_name, ()))):
        role = "primary" if index == 0 else "fallback"
        try:
            judge = JUDGES[name]()
        except (ValueError, ImportError) as exc:
            console.print(f"[yellow]{role} {name}: not configured[/yellow] — {_scrub(str(exc))}")
            continue
        model = getattr(judge, "model", None)
        try:
            verdict = asyncio.run(judge.analyze(probe, "4."))
        except Exception as exc:  # noqa: BLE001 - reported, never raised
            console.print(f"[red]{role} {name} ({model}): failed[/red] — {_scrub(str(exc))[:200]}")
            continue
        if verdict.confidence_score > 0.0:
            console.print(
                f"[green]{role} {name} ({model}): answered[/green] — "
                f"verdict {verdict.verdict.value if verdict.verdict else '?'}"
            )
            primary_ok = primary_ok or index == 0
        else:
            console.print(
                f"[red]{role} {name} ({model}): no verdict[/red] — "
                f"{_scrub(verdict.reasoning or '')[:200]}"
            )

    if not primary_ok:
        raise SystemExit(2)


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


_ACTIONS = {
    "c": "confirm",
    "v": "vulnerable",
    "h": "held",
    "n": "needs_review",
    "s": "skip",
    "q": "quit",
}

_VERDICT_STYLE = {
    "vulnerable": "red",
    "held": "green",
    "needs_review": "yellow",
}


def _show_case(
    case: BenchmarkCase, position: int, total: int, remaining: dict[str, int]
) -> None:
    """Print everything needed to decide, so nothing has to be looked up elsewhere."""
    left = "  ".join(f"{verdict}: {count}" for verdict, count in remaining.items() if count)
    console.rule(f"[bold]{case.id}[/bold]  ·  {position} of {total} in this queue")
    console.print(f"[dim]remaining unreviewed — {left}[/dim]\n")

    console.print(
        Panel(
            f"[bold]{case.attack_name}[/bold]  [dim]({case.attack_id})[/dim]\n\n"
            f"[bold]what it attempts[/bold]\n{case.attack_intent}\n\n"
            f"[bold]counts as success[/bold]\n{case.success_criteria}",
            title="the attack",
            border_style="cyan",
        )
    )

    prompt_key = str(case.source.get("prompt") or "")
    prompt_text = resolve_prompt(prompt_key)
    console.print(
        Panel(
            prompt_text or "[dim](not recorded for this case)[/dim]",
            title=f"system prompt under attack — {prompt_key or 'unknown'}",
            border_style="blue",
        )
    )

    target = str(case.source.get("target_model") or "unknown")
    console.print(
        Panel(
            case.response,
            title=f"what {target} actually replied",
            border_style="magenta",
        )
    )

    style = _VERDICT_STYLE.get(case.verdict, "white")
    console.print(
        Panel(
            f"[bold {style}]{case.verdict}[/bold {style}]\n\n{case.rationale}",
            title=f"proposed label — {case.proposed_by}",
            border_style=style,
        )
    )


@evaluate.command("review")
@click.option(
    "--benchmark", "benchmark_path", type=click.Path(path_type=Path),
    help="Benchmark file (defaults to the packaged one).",
)
@click.option(
    "--reviewer", default=None,
    help="Recorded against each decision. Defaults to your git user.name.",
)
@click.option(
    "--only", "only", multiple=True, metavar="CASE_ID",
    help="Review just these cases, in this order, re-opening them even if already "
         "REVIEWED. Repeat the option or pass a comma-separated list.",
)
def evaluate_review(
    benchmark_path: Path | None, reviewer: str | None, only: tuple[str, ...]
) -> None:
    """Review unreviewed cases one at a time, confirming or correcting each label.

    Vulnerable cases come first: they are the smallest class, they are what
    recall is computed from, and a wrong one costs more than a wrong held.

    The file is written after every decision, so stopping partway — or losing
    the terminal — keeps everything already decided.
    """
    benchmark = load_benchmark(benchmark_path)
    path = benchmark.path
    if path is None:
        raise SystemExit("benchmark has no path on disk to save to")

    who = reviewer or default_reviewer()
    case_ids = [part.strip() for value in only for part in value.split(",") if part.strip()]
    try:
        queue = review_queue(benchmark, only=case_ids or None)
    except ReviewError as exc:
        raise click.UsageError(str(exc)) from exc
    if not queue:
        console.print(
            f"[green]Nothing to review.[/green] All {len(benchmark)} case(s) in "
            f"benchmark v{benchmark.version} are REVIEWED."
        )
        return

    console.print(
        f"[bold]{len(queue)}[/bold] {'selected' if case_ids else 'unreviewed'} case(s) · "
        f"reviewing as [cyan]{who}[/cyan] · saving to {path}\n"
    )

    decided = 0
    skipped = 0
    for position, case in enumerate(queue, start=1):
        current = next(c for c in benchmark.cases if c.id == case.id)
        _show_case(current, position, len(queue), queue_summary(benchmark))

        try:
            choice = click.prompt(
                "[c]onfirm  [v]ulnerable  [h]eld  [n]eeds_review  [s]kip  [q]uit",
                type=click.Choice(sorted(_ACTIONS)),
                show_choices=False,
            )
        except (click.Abort, EOFError):
            console.print("\n[yellow]Stopped.[/yellow]")
            break

        action = _ACTIONS[choice]
        if action == "quit":
            break
        if action == "skip":
            skipped += 1
            console.print("[dim]skipped — still UNREVIEWED[/dim]\n")
            continue

        if action != "confirm" and action == current.verdict:
            # Caught before asking for a reason: the problem is the choice, not
            # the wording, so re-prompting for a better reason would never end.
            console.print(
                f"[yellow]{current.id} is already labeled {action} — "
                f"press c to confirm it.[/yellow]\n"
            )
            skipped += 1
            continue

        if action == "confirm":
            updated = confirm_case(current, who)
        else:
            reason = ""
            while True:
                try:
                    reason = click.prompt(f"one line on why it is {action}")
                except (click.Abort, EOFError):
                    reason = ""
                    break
                try:
                    updated = change_case(current, action, reason, who)
                    break
                except ReviewError as exc:
                    console.print(f"[red]{exc}[/red]")
            if not reason:
                console.print("[yellow]No reason given — left UNREVIEWED.[/yellow]\n")
                skipped += 1
                continue

        benchmark = apply_decision(benchmark, updated)
        dump_benchmark(benchmark, path)
        decided += 1
        verb = "confirmed" if action == "confirm" else f"changed to {action}"
        console.print(f"[green]{current.id} {verb} and saved[/green]\n")

    remaining = queue_summary(benchmark)
    console.print(
        f"\n[bold]{decided} decided[/bold], {skipped} skipped this session · "
        f"{len(benchmark.reviewed())}/{len(benchmark)} reviewed overall"
    )
    left = "  ".join(f"{v}: {n}" for v, n in remaining.items() if n)
    if left:
        console.print(f"still unreviewed — {left}")
