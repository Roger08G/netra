from __future__ import annotations

import json
import os
import string
import sys
from pathlib import Path
from typing import Any, Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .diffing import compare_artifacts
from .engine import EngineError, final_payload, request
from .render import build_html

app = typer.Typer(
    name="netra",
    help="Descubrimiento y topología de red basados en evidencias.",
    no_args_is_help=True,
)
console = Console(stderr=False)
err_console = Console(stderr=True)


def _version(value: bool) -> None:
    if value:
        console.print(f"netra {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version, is_eager=True, help="Muestra la versión."),
    ] = None,
) -> None:
    """Netra mantiene separadas observación, inferencia y certeza."""


@app.command()
def doctor(
    json_output: Annotated[bool, typer.Option("--json", help="Emite JSON.")] = False,
) -> None:
    """Comprueba motor, plataforma y capacidades disponibles."""
    try:
        result = final_payload(request("doctor"), "doctor.completed")
    except EngineError as exc:
        _fail(exc)
    engine_version = str(result.get("product_version", "desconocida"))
    versions_match = engine_version == __version__
    result["cli_version"] = __version__
    result["compatible"] = versions_match
    if json_output:
        _json(result)
        if not versions_match:
            raise typer.Exit(1)
        return
    table = Table(title="Netra doctor", show_header=True)
    table.add_column("Capacidad")
    table.add_column("Estado")
    table.add_column("Detalle")
    table.add_row(
        "version",
        "[green]correcta[/green]" if versions_match else "[red]no coincide[/red]",
        f"CLI {__version__} / motor {engine_version}",
    )
    for item in result.get("capabilities", []):
        state = "[green]disponible[/green]" if item.get("available") else "[yellow]no disponible[/yellow]"
        table.add_row(str(item.get("name")), state, str(item.get("detail", "")))
    console.print(table)
    for note in result.get("notes", []):
        console.print(f"[dim]• {note}[/dim]")
    if not versions_match:
        raise typer.Exit(1)


@app.command()
def plan(
    scope: Annotated[list[str] | None, typer.Option("--scope", help="CIDR autorizado; repetible.")] = None,
    interface: Annotated[str | None, typer.Option("--interface", help="Interfaz de red.")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="IP o CIDR excluido; repetible.")] = None,
    passive: Annotated[bool, typer.Option("--passive", help="No planifica sondas activas.")] = False,
    output: Annotated[Path, typer.Option("--output", "-o", help="Ruta del plan JSON.")] = Path("plan.json"),
    json_output: Annotated[bool, typer.Option("--json", help="Emite el plan por stdout.")] = False,
) -> None:
    """Prepara y valida un alcance sin sondear la red."""
    payload = {
        "scope": scope or [],
        "interface": interface or "",
        "exclude": exclude or [],
        "passive": passive,
    }
    try:
        result = final_payload(request("plan.create", payload), "plan.completed")
    except EngineError as exc:
        _fail(exc)
    plan_data = result["plan"]
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if json_output:
        _json(plan_data)
    else:
        _print_plan(plan_data)
        console.print(f"\nPlan guardado en [cyan]{escape(str(output))}[/cyan]")


@app.command()
def scan(
    plan_file: Annotated[Path | None, typer.Option("--plan", help="Plan JSON aprobado.")] = None,
    scope: Annotated[list[str] | None, typer.Option("--scope", help="CIDR autorizado; repetible.")] = None,
    interface: Annotated[str | None, typer.Option("--interface", help="Interfaz de red.")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="IP o CIDR excluido; repetible.")] = None,
    passive: Annotated[bool, typer.Option("--passive", help="Evita toda sonda activa.")] = False,
    services: Annotated[bool, typer.Option("--services", help="Comprueba puertos TCP comunes.")] = False,
    evidence: Annotated[Path | None, typer.Option("--evidence", help="Observaciones FDB/LLDP en JSON.")] = None,
    snmp_config: Annotated[Path | None, typer.Option("--snmp-config", help="Configuración SNMPv3 con referencias a variables de entorno.")] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", min=1, max=256)] = 64,
    timeout: Annotated[float, typer.Option("--timeout", min=0.05, max=10.0)] = 0.5,
    output: Annotated[Path, typer.Option("--output", "-o", help="Artefacto JSON de la ejecución.")] = Path("runs/latest.json"),
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Acepta el alcance no interactivo.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emite eventos NDJSON.")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True, help="Aumenta el detalle.")] = 0,
) -> None:
    """Descubre activos dentro de un alcance aprobado y conserva la evidencia."""
    try:
        plan_data = _load_or_create_plan(plan_file, scope, interface, exclude, passive)
    except (EngineError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        _fail(exc)

    if not yes and not plan_data.get("passive") and sys.stdin.isatty():
        _print_plan(plan_data)
        if not typer.confirm("Ejecutar exactamente este alcance?"):
            raise typer.Abort()
    elif not yes and not plan_data.get("passive"):
        _fail(ValueError("Una ejecución activa no interactiva requiere --yes o un terminal interactivo."))

    evidence_data: dict[str, Any] | None = None
    if evidence:
        try:
            evidence_data = json.loads(evidence.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _fail(ValueError(f"No se pudo leer --evidence: {exc}"))

    snmp_data: dict[str, Any] | None = None
    if snmp_config:
        try:
            snmp_data = _load_snmp_config(snmp_config)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            _fail(ValueError(f"No se pudo preparar --snmp-config: {exc}"))

    output = output.resolve()
    payload = {
        "plan": plan_data,
        "services": services,
        "concurrency": concurrency,
        "timeout_ms": int(timeout * 1000),
        "output": str(output),
        "managed_evidence": evidence_data,
        "snmp": snmp_data,
    }

    def show_event(event: dict[str, Any]) -> None:
        if json_output:
            print(json.dumps(event, ensure_ascii=False), flush=True)
        elif verbose and event.get("type") != "observation.recorded":
            console.print(f"[dim]{event.get('type')}[/dim]")

    try:
        completed = final_payload(
            request("scan.execute", payload, on_event=show_event), "run.completed"
        )
    except EngineError as exc:
        _fail(exc)
    if not json_output:
        summary = completed.get("summary", {})
        console.print(
            Panel.fit(
                f"[green]Ejecución completada[/green]\n"
                f"Activos: [bold]{summary.get('assets', 0)}[/bold]  "
                f"Relaciones: [bold]{summary.get('relationships', 0)}[/bold]  "
                f"Incidencias de cobertura: [bold]{summary.get('issues', 0)}[/bold]\n"
                f"Artefacto: [cyan]{escape(str(completed.get('artifact', output)))}[/cyan]",
                title="Netra",
            )
        )


@app.command()
def graph(
    run_file: Annotated[Path, typer.Argument(help="Artefacto JSON de una ejecución.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Informe HTML.")] = Path("reports/netra-report.html"),
) -> None:
    """Genera un mapa HTML local y autocontenido."""
    try:
        artifact = json.loads(run_file.read_text(encoding="utf-8"))
        _validate_artifact(artifact)
        output = output.resolve()
        build_html(artifact, output)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        _fail(exc)
    console.print(f"Informe generado en [cyan]{escape(str(output))}[/cyan]")


@app.command()
def inventory(
    run_file: Annotated[Path, typer.Argument(help="Artefacto JSON de una ejecución.")],
    explain: Annotated[bool, typer.Option("--explain", help="Muestra evidencia resumida.")] = False,
) -> None:
    """Muestra el inventario de una ejecución."""
    try:
        artifact = json.loads(run_file.read_text(encoding="utf-8"))
        _validate_artifact(artifact)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        _fail(exc)
    table = Table(title="Inventario Netra")
    table.add_column("Activo")
    table.add_column("Direcciones")
    table.add_column("MAC")
    table.add_column("Roles")
    if explain:
        table.add_column("Evidencia")
    for asset in artifact.get("assets", []):
        row = [
            escape(str((asset.get("names") or [asset.get("id")])[0])),
            escape(", ".join(asset.get("addresses", [])) or "—"),
            escape(", ".join(asset.get("macs", [])) or "—"),
            escape(", ".join(asset.get("roles", [])) or "unknown"),
        ]
        if explain:
            row.append(escape(", ".join(item.get("source", "?") for item in asset.get("evidence", [])) or "—"))
        table.add_row(*row)
    console.print(table)


@app.command(name="diff")
def diff_runs(
    before_file: Annotated[Path, typer.Argument(help="Artefacto anterior.")],
    after_file: Annotated[Path, typer.Argument(help="Artefacto posterior.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emite el detalle JSON.")] = False,
) -> None:
    """Compara dos ejecuciones sin confundir cambios de marca temporal con cambios de red."""
    try:
        before = json.loads(before_file.read_text(encoding="utf-8"))
        after = json.loads(after_file.read_text(encoding="utf-8"))
        _validate_artifact(before)
        _validate_artifact(after)
        result = compare_artifacts(before, after)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        _fail(exc)
    if json_output:
        _json(result)
        return
    summary = result["summary"]
    table = Table(title="Cambios entre ejecuciones")
    table.add_column("Categoría")
    table.add_column("Añadidos", justify="right")
    table.add_column("Retirados", justify="right")
    table.add_column("Modificados", justify="right")
    table.add_row("Activos", str(summary["assets_added"]), str(summary["assets_removed"]), str(summary["assets_changed"]))
    table.add_row("Servicios", str(summary["services_added"]), str(summary["services_removed"]), "—")
    table.add_row("Relaciones", str(summary["relationships_added"]), str(summary["relationships_removed"]), "—")
    console.print(table)


def _load_or_create_plan(
    plan_file: Path | None,
    scope: list[str] | None,
    interface: str | None,
    exclude: list[str] | None,
    passive: bool,
) -> dict[str, Any]:
    if plan_file:
        if any((scope, interface, exclude, passive)):
            raise ValueError("--plan no se puede combinar con opciones que modifican el alcance.")
        plan_data = json.loads(plan_file.read_text(encoding="utf-8"))
        if not isinstance(plan_data, dict):
            raise ValueError("El plan debe ser un objeto JSON.")
        return plan_data
    result = final_payload(
        request(
            "plan.create",
            {"scope": scope or [], "interface": interface or "", "exclude": exclude or [], "passive": passive},
        ),
        "plan.completed",
    )
    return result["plan"]


def _print_plan(plan_data: dict[str, Any]) -> None:
    console.print(
        Panel.fit(
            f"Interfaz: [bold]{plan_data.get('interface') or 'automática'}[/bold]\n"
            f"Alcance: [cyan]{', '.join(plan_data.get('scope') or [])}[/cyan]\n"
            f"Exclusiones: {', '.join(plan_data.get('exclude') or []) or '—'}\n"
            f"Modo: {'pasivo' if plan_data.get('passive') else 'activo de bajo impacto'}\n"
            f"Objetivos IPv4 máximos: {plan_data.get('target_count', 0)}",
            title="Plan propuesto",
        )
    )


def _validate_artifact(artifact: dict[str, Any]) -> None:
    if artifact.get("schema_version") != "1.0.0":
        raise ValueError("Versión de artefacto no compatible.")
    if not isinstance(artifact.get("assets"), list) or not isinstance(artifact.get("relationships"), list):
        raise ValueError("El artefacto no contiene activos y relaciones válidos.")


def _load_snmp_config(path: Path) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("la configuración debe ser un objeto JSON")
    if config.get("schema_version") != "1.0.0":
        raise ValueError("schema_version debe ser 1.0.0")
    unexpected_root = set(config) - {"schema_version", "targets"}
    if unexpected_root:
        raise ValueError(f"claves no permitidas: {', '.join(sorted(unexpected_root))}")
    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets debe ser una lista no vacía")
    resolved: list[dict[str, Any]] = []
    allowed_target_keys = {
        "address",
        "port",
        "timeout_ms",
        "retries",
        "username",
        "auth_protocol",
        "auth_passphrase_env",
        "privacy_protocol",
        "privacy_passphrase_env",
        "context_name",
    }
    for index, target in enumerate(targets, start=1):
        if not isinstance(target, dict):
            raise ValueError(f"targets[{index}] debe ser un objeto")
        if "auth_passphrase" in target or "privacy_passphrase" in target:
            raise ValueError(
                f"targets[{index}] contiene un secreto directo; usa las claves *_env"
            )
        unexpected = set(target) - allowed_target_keys
        if unexpected:
            raise ValueError(
                f"targets[{index}] contiene claves no permitidas: {', '.join(sorted(unexpected))}"
            )
        auth_env = target.get("auth_passphrase_env")
        privacy_env = target.get("privacy_passphrase_env")
        if not isinstance(auth_env, str) or not auth_env:
            raise ValueError(f"targets[{index}].auth_passphrase_env es obligatorio")
        if not isinstance(privacy_env, str) or not privacy_env:
            raise ValueError(f"targets[{index}].privacy_passphrase_env es obligatorio")
        for variable in (auth_env, privacy_env):
            suffix = variable.removeprefix("NETRA_SNMP_")
            valid_characters = set(string.ascii_uppercase + string.digits + "_")
            if not suffix or not variable.startswith("NETRA_SNMP_") or any(
                character not in valid_characters for character in suffix
            ):
                raise ValueError(
                    f"targets[{index}] usa una variable no permitida; debe empezar por NETRA_SNMP_"
                )
        try:
            auth_secret = os.environ[auth_env]
            privacy_secret = os.environ[privacy_env]
        except KeyError as exc:
            raise ValueError(f"falta la variable de entorno {exc.args[0]}") from None
        item = {
            key: value
            for key, value in target.items()
            if key not in {"auth_passphrase_env", "privacy_passphrase_env"}
        }
        item["auth_passphrase"] = auth_secret
        item["privacy_passphrase"] = privacy_secret
        resolved.append(item)
    return {"schema_version": config["schema_version"], "targets": resolved}


def _json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _fail(exc: Exception) -> None:
    err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
    raise typer.Exit(1)
