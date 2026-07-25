"""Command line interface.

`rotate` is a dry run unless you pass `--execute`, and it will not revoke an old
version without verifying that consumers migrated. Both defaults exist because
the alternative is an outage on the one occasion nobody is watching.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .backends import BackendError, available, get
from .model import InventoryError, load, save
from .rotation import Outcome, RotationResult, due, plan, rotate

STATUS_STYLE = {
    "overdue": "bright_red",
    "due soon": "yellow",
    "rotating": "cyan",
    "ok": "green",
    "uninitialised": "magenta",
}
OUTCOME_STYLE = {
    Outcome.OK: "green",
    Outcome.PLANNED: "blue",
    Outcome.SKIPPED: "yellow",
    Outcome.FAILED: "bright_red",
    Outcome.ROLLED_BACK: "magenta",
}


def _age(days: int | None) -> Text:
    if days is None:
        return Text("never rotated", style="magenta")
    if days < 0:
        return Text(f"{abs(days)}d overdue", style="bright_red")
    return Text(f"{days}d left", style="yellow" if days <= 30 else "dim")


def cmd_inventory(args: argparse.Namespace, console: Console) -> int:
    inventory = load(args.inventory)

    overdue = inventory.overdue()
    soon = inventory.due_soon()
    unrevoked = inventory.unrevoked()

    header = Text()
    header.append(f"{len(inventory)} secrets\n", style="bold")
    header.append(f"{len(overdue)} overdue   ", style="bright_red" if overdue else "dim")
    header.append(f"{len(soon)} due soon   ", style="yellow" if soon else "dim")
    header.append(
        f"{len(unrevoked)} unrevoked predecessor(s)",
        style="bright_red" if unrevoked else "dim",
    )
    console.print(Panel(header, title="slm inventory", border_style="blue", expand=False))

    table = Table(header_style="dim")
    table.add_column("secret", style="bold")
    table.add_column("kind", style="cyan")
    table.add_column("owner")
    table.add_column("status")
    table.add_column("rotation", justify="right")
    table.add_column("overlap", justify="right", style="dim")
    table.add_column("consumers", style="dim", overflow="fold")

    for secret in sorted(
        inventory.secrets,
        key=lambda s: (s.days_remaining if s.days_remaining is not None else -99999),
    ):
        owner = Text(secret.owner)
        if secret.owner.lower() in ("unassigned", "unknown", ""):
            owner = Text(secret.owner or "unassigned", style="bright_red")
        table.add_row(
            secret.id,
            secret.kind.label,
            owner,
            Text(secret.status, style=STATUS_STYLE.get(secret.status, "white")),
            _age(secret.days_remaining),
            f"{int(secret.overlap.total_seconds() // 3600)}h" if secret.overlap else "none",
            ", ".join(secret.consumers),
        )
    console.print(table)

    if unrevoked:
        console.print()
        table = Table(
            title="Superseded versions that were never revoked",
            title_style="bold", header_style="dim",
        )
        table.add_column("secret", style="bold")
        table.add_column("version", justify="right")
        table.add_column("issued", style="dim")
        table.add_column("note", overflow="fold")
        for secret, version in unrevoked:
            table.add_row(
                secret.id, str(version.version),
                version.created_at.date().isoformat(), version.note,
            )
        console.print(table)
        console.print(
            "[dim]Rotation without revocation only increases the number of live "
            "credentials.[/]"
        )

    if args.json:
        Path(args.json).write_text(json.dumps(inventory.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {args.json}[/]")
    return 0


def cmd_check(args: argparse.Namespace, console: Console) -> int:
    """The command a scheduler runs. Exits non-zero when something needs doing."""
    inventory = load(args.inventory)
    horizon = timedelta(days=args.within)
    pending = due(inventory.secrets, horizon)
    unrevoked = inventory.unrevoked()

    if not pending and not unrevoked:
        console.print(
            f"[bold green]nothing due[/] within {args.within} day(s), and no "
            "unrevoked predecessors."
        )
        return 0

    if pending:
        table = Table(
            title=f"Due within {args.within} day(s)", title_style="bold", header_style="dim"
        )
        table.add_column("secret", style="bold")
        table.add_column("owner")
        table.add_column("when", justify="right")
        table.add_column("why", overflow="fold")
        for secret in pending:
            if secret.days_remaining is None:
                why = "never rotated"
            elif secret.current and secret.current.expires_at and (
                secret.current.expires_at < secret.current.created_at + secret.max_age
            ):
                why = "the certificate expires before the rotation policy comes due"
            else:
                why = f"older than the {secret.max_age.days}-day policy"
            table.add_row(secret.id, secret.owner, _age(secret.days_remaining), why)
        console.print(table)

    if unrevoked:
        console.print(
            f"\n[bright_red]{len(unrevoked)} superseded version(s) are still valid:[/] "
            + ", ".join(f"{s.id} v{v.version}" for s, v in unrevoked)
        )

    return 1 if args.fail else 0


def cmd_rotate(args: argparse.Namespace, console: Console) -> int:
    inventory = load(args.inventory)
    targets = (
        [s for s in inventory.secrets if s.id in set(args.secret)]
        if args.secret
        else due(inventory.secrets, timedelta(days=args.within))
    )
    if not targets:
        console.print("[yellow]nothing to rotate[/]")
        return 0

    missing = set(args.secret or []) - {s.id for s in targets}
    if missing:
        console.print(f"[red]no such secret:[/] {', '.join(sorted(missing))}")
        return 2

    exit_code = 0
    for secret in targets:
        try:
            backend = get(secret.backend)
        except BackendError as exc:
            console.print(f"[bold red]{secret.id}:[/] {exc}")
            exit_code = 1
            continue

        result = rotate(
            secret, backend,
            dry_run=not args.execute,
            skip_verify=args.skip_verify,
            force_revoke=args.force_revoke,
        )
        _render(secret.id, result, console)
        if not result.ok:
            exit_code = 1

    if args.execute and args.write:
        save(inventory, args.write)
        console.print(f"[dim]wrote {args.write}[/]")

    if not args.execute:
        console.print(
            "\n[dim]nothing was changed. Add --execute to rotate for real.[/]"
        )
    return exit_code


def _render(secret_id: str, result: RotationResult, console: Console) -> None:
    header = Text()
    header.append(f"{secret_id}", style="bold")
    if result.dry_run:
        header.append("   DRY RUN", style="bold blue")
    elif result.completed:
        header.append("   rotated and old version revoked", style="bold green")
    elif result.rolled_back:
        header.append("   failed and rolled back", style="bold magenta")
    elif result.ok:
        header.append("   rotated, old version still valid", style="bold yellow")
    else:
        header.append("   FAILED", style="bold bright_red")
    console.print(Panel(header, border_style="blue", expand=False))

    table = Table(header_style="dim", show_header=True)
    table.add_column("phase", style="bold")
    table.add_column("outcome")
    table.add_column("what happened", overflow="fold")
    for record in result.records:
        table.add_row(
            record.phase.value,
            Text(record.outcome.value, style=OUTCOME_STYLE[record.outcome]),
            record.message,
        )
    console.print(table)


def cmd_plan(args: argparse.Namespace, console: Console) -> int:
    inventory = load(args.inventory)
    secret = inventory.get(args.secret)
    if secret is None:
        console.print(f"[red]no secret {args.secret!r}[/]")
        return 2

    body = Text()
    body.append(f"{secret.description or secret.kind.label}\n\n", style="dim")
    body.append("owner      ", style="dim")
    body.append(f"{secret.owner}\n")
    body.append("backend    ", style="dim")
    body.append(f"{secret.backend}\n")
    body.append("consumers  ", style="dim")
    body.append(f"{', '.join(secret.consumers) or 'none recorded'}\n")
    body.append("overlap    ", style="dim")
    if secret.kind.supports_overlap and secret.overlap:
        body.append(f"{int(secret.overlap.total_seconds() // 3600)}h\n")
    else:
        body.append("not possible for this kind — direct cutover\n", style="yellow")
    console.print(Panel(body, title=secret.id, border_style="blue", expand=False))

    for index, step in enumerate(plan(secret), start=1):
        console.print(f"  [bold]{index}.[/] {step}")
    console.print(
        "\n[dim]Step 3 is the one that gets skipped, and skipping it is what turns "
        "step 4 into an outage.[/]"
    )
    return 0


def cmd_backends(args: argparse.Namespace, console: Console) -> int:
    table = Table(title="Registered backends", title_style="bold", header_style="dim")
    table.add_column("name", style="bold")
    table.add_column("create")
    table.add_column("verify")
    table.add_column("revoke")
    table.add_row("simulated", "yes", "asks the consumers", "yes")
    table.add_row(
        "read-only", Text("no", style="yellow"), "reports every consumer as unmigrated",
        Text("no", style="yellow"),
    )
    console.print(table)
    console.print(
        f"\n[dim]{', '.join(available())}. A backend is four methods: create, "
        "promote, verify, revoke. Wiring one to Vault or AWS Secrets Manager is "
        "those four; the state machine and the refusal to revoke unverified are "
        "what this provides.[/]"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slm", description="Secret rotation with an overlap window and a way back."
    )
    parser.add_argument("--version", action="version", version=f"slm {__version__}")
    parser.add_argument("--inventory", default="inventory.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inventory", help="show every secret and its status")
    p.add_argument("--json")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("check", help="what is due — for a scheduler")
    p.add_argument("--within", type=int, default=0, help="days of look-ahead")
    p.add_argument("--fail", action="store_true", help="exit 1 when something is due")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("plan", help="the phases a rotation would go through")
    p.add_argument("secret")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("rotate", help="rotate (dry run unless --execute)")
    p.add_argument("secret", nargs="*", help="ids; default is everything due")
    p.add_argument("--within", type=int, default=0)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--skip-verify", action="store_true",
                   help="do not check consumers migrated (the old version stays valid)")
    p.add_argument("--force-revoke", action="store_true",
                   help="revoke without verification — accepts that consumers may break")
    p.add_argument("--write", help="write the updated inventory here")
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("backends", help="list the registered backends")
    p.set_defaults(func=cmd_backends)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except InventoryError as exc:
        console.print(f"[bold red]inventory error:[/] {exc}")
        return 2
    except BackendError as exc:
        console.print(f"[bold red]backend error:[/] {exc}")
        return 2
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
