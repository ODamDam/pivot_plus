from collections import defaultdict
from typing import Generator

from scanner.pyrit.runner import run_scorer
from scanner.pyrit.result_writer import init_result_files, write_result

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()


def execute(payload: Generator) -> None:
    config_info = init_result_files(
        report_prefix="pyrit_run",
        report_dir="scanner/pyrit/data"
    )

    console.print(Panel("[bold cyan]선택된 스캐너: pyrit[/bold cyan]", expand=False))

    goal_stats = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})

    row_table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    row_table.add_column("row", style="dim", width=5)
    row_table.add_column("seed_id", style="cyan", width=20)
    row_table.add_column("결과", width=8)
    row_table.add_column("판단 근거", style="dim")
    row_table.add_column("goal", style="dim")

    for row_idx, input_data in enumerate(payload, start=1):
        seed_id = input_data.get("seed_id", "")
        scorer_result = run_scorer(input_data)
        write_result(input_data, scorer_result)

        final = "PASS" if scorer_result["passed"] else "FAIL"
        result_text = "[bold green]PASS[/bold green]" if final == "PASS" else "[bold red]FAIL[/bold red]"
        rationale = scorer_result.get("score_rationale", "") if not scorer_result["passed"] else ""

        row_table.add_row(
            str(row_idx),
            str(seed_id),
            result_text,
            rationale,
            input_data["goal"],
        )

        goal = input_data["goal"]
        goal_stats[goal]["total"] += 1
        goal_stats[goal]["passed"] += (1 if final == "PASS" else 0)
        goal_stats[goal]["failed"] += (1 if final == "FAIL" else 0)

    console.print(row_table)

    total = sum(s["total"] for s in goal_stats.values())
    passed = sum(s["passed"] for s in goal_stats.values())
    failed = sum(s["failed"] for s in goal_stats.values())
    rate = (failed / total * 100) if total > 0 else 0.0

    console.print(f"전체  시도: {total}개 / [bold green]PASS[/bold green]: {passed}개 / [bold red]FAIL[/bold red]: {failed}개 / 공격성공률: {rate:.1f}%")
    console.print(f"[dim]리포트: {config_info['report_filename']}[/dim]")