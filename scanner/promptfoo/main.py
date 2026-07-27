from typing import Generator

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

from scanner.promptfoo.runner import run_promptfoo
from scanner.promptfoo.result_writer import init_result_files, write_result

console = Console()


def execute(payload: Generator) -> None:
    config_info = init_result_files(
        report_prefix="promptfoo_run",
        report_dir="scanner/promptfoo/data"
    )

    console.print(Panel("[bold cyan]선택된 스캐너: promptfoo[/bold cyan]", expand=False))

    # payload를 한 번에 리스트로 수집 (promptfoo는 배치로 실행)
    records = list(payload)

    results = run_promptfoo(records)

    row_table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    row_table.add_column("row", style="dim", width=5)
    row_table.add_column("seed_id", style="cyan", width=20)
    row_table.add_column("결과", width=8)
    row_table.add_column("판단 근거", style="dim")
    row_table.add_column("goal", style="dim")

    total = passed_count = failed_count = 0

    for row_idx, (record, result) in enumerate(zip(records, results), start=1):
        passed = result["passed"]
        final = "PASS" if passed else "FAIL"
        result_text = "[bold green]PASS[/bold green]" if passed else "[bold red]FAIL[/bold red]"
        reason = result.get("reason", "") if not passed else "-"

        row_table.add_row(
            str(row_idx),
            str(result["seed_id"]),
            result_text,
            reason,
            record.get("bucket_id", ""),
        )

        write_result(record, result)

        total += 1
        passed_count += (1 if passed else 0)
        failed_count += (1 if not passed else 0)

    console.print(row_table)

    rate = (failed_count / total * 100) if total > 0 else 0.0
    console.print(f"전체  시도: {total}개 / [bold green]PASS[/bold green]: {passed_count}개 / [bold red]FAIL[/bold red]: {failed_count}개 / 공격성공률: {rate:.1f}%")
    console.print(f"[dim]리포트: {config_info['report_filename']}[/dim]")