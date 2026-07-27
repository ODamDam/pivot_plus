from collections import defaultdict

from scanner.garak.config import init_garak_config
from scanner.garak.runner import run_detectors
from scanner.garak.result_writer import write_attempt_result

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()


def summarize(detector_results: dict) -> tuple[int, int]:
    passed, failed = 0, 0
    for result in detector_results.values():
        if result is None:
            continue
        if result["passed"]:
            passed += 1
        else:
            failed += 1
    return passed, failed


def execute(attempts):
    config_info = init_garak_config(
        report_prefix="scanner_run",
        report_dir="scanner/garak/data"
    )

    console.print(Panel("[bold cyan]선택된 스캐너: garak[/bold cyan]", expand=False))

    goal_stats = defaultdict(lambda: {"total": 0, "passed": 0, "failed": 0})

    row_table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    row_table.add_column("row", style="dim", width=5)
    row_table.add_column("seed_id", style="cyan", width=20)
    row_table.add_column("결과", width=8)
    row_table.add_column("PASS/FAIL", width=12)
    row_table.add_column("걸린 detector")
    row_table.add_column("goal", style="dim")

    for row_idx, attempt in enumerate(attempts, start=1):
        seed_id = attempt.notes.get('seed_id', 'Unknown')
        detector_results = run_detectors(attempt)
        write_attempt_result(attempt, detector_results)

        passed, failed = summarize(detector_results)
        final = "FAIL" if failed > 0 else "PASS"
        result_text = "[bold green]PASS[/bold green]" if final == "PASS" else "[bold red]FAIL[/bold red]"
        pass_fail_summary = f"[green]{passed}[/green] / [red]{failed}[/red]"

        failed_detectors = ", ".join([
            d.rsplit(".", 1)[-1]
            for d, r in detector_results.items()
            if r is not None and not r["passed"]
        ])

        row_table.add_row(
            str(row_idx),
            str(seed_id),
            result_text,
            pass_fail_summary,
            f"[red]{failed_detectors}[/red]" if failed_detectors else "[dim]-[/dim]",
            attempt.goal,
        )

        goal = attempt.goal
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


if __name__ == "__main__":
    console.print("[dim][System] 이 모듈은 단독으로 실행할 수 없습니다. 'python -m scanner.main'을 통해 실행해주세요.[/dim]")