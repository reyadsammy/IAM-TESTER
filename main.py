"""IAM Security Tester - CLI Entry Point."""

import sys
import click
from config import ScanConfig
from runner import TestRunner, ALL_CATEGORIES
from reporter import print_console_report, generate_html_report


@click.command()
@click.option("--target", default="http://localhost:8000", help="Target API base URL")
@click.option("--categories", default=None, help="Comma-separated attack categories to run")
@click.option("--output", default="./reports", help="Report output directory")
@click.option("--format", "fmt", default="both", type=click.Choice(["console", "html", "both"]))
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--no-dos", is_flag=True, help="Skip DoS/rate-limit tests")
@click.option("--timeout", default=10, help="Request timeout in seconds")
@click.option("--push", is_flag=True, help="Push results to IAM dashboard after scan")
@click.option("--list-categories", is_flag=True, help="List available attack categories and exit")
def main(target, categories, output, fmt, verbose, no_dos, timeout, push, list_categories):
    """IAM Security Tester - External black-box security testing for Agentic-IAM."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    if list_categories:
        console.print("[bold]Available attack categories:[/]")
        for cat in ALL_CATEGORIES:
            console.print(f"  - {cat}")
        return

    # Banner
    console.print()
    console.print(Panel.fit(
        "[bold bright_blue]IAM Security Tester[/]\n"
        "[dim]External black-box security testing for Agentic-IAM[/]",
        border_style="bright_blue",
    ))
    console.print()

    # Build config
    config = ScanConfig(
        target_url=target,
        timeout=timeout,
        output_dir=output,
        categories=categories.split(",") if categories else None,
        skip_dos=no_dos,
        verbose=verbose,
    )

    runner = TestRunner(config)

    # Connectivity check
    connected, msg = runner.check_connectivity()
    if not connected:
        console.print(f"[red]Cannot connect to {target}: {msg}[/]")
        console.print("[dim]Make sure the IAM API is running.[/]")
        sys.exit(1)
    console.print(f"[green]Connected to {target}[/] ({msg})")
    console.print()

    # Run scan with progress
    from rich.progress import Progress
    with Progress() as progress:
        modules = runner.get_modules()
        task = progress.add_task("[bright_blue]Running security scan...", total=len(modules))

        def on_progress(name, idx, total):
            progress.update(task, completed=idx, description=f"[bright_blue]Testing: {name}")

        scan = runner.run(progress_callback=on_progress)
        progress.update(task, completed=len(modules), description="[green]Scan complete")

    # Reports
    if fmt in ("console", "both"):
        print_console_report(scan)

    if fmt in ("html", "both"):
        report_path = generate_html_report(scan, output)
        console.print(f"[green]HTML report saved:[/] {report_path}")

    # Push to IAM
    if push:
        console.print()
        success, msg = runner.push_results_to_iam(scan)
        if success:
            console.print(f"[green]{msg}[/]")
        else:
            console.print(f"[yellow]{msg}[/]")

    # Exit code
    from models import Severity
    critical_high = (
        scan.findings_by_severity.get(Severity.CRITICAL, 0)
        + scan.findings_by_severity.get(Severity.HIGH, 0)
    )
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
