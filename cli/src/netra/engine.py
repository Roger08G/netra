from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any


class EngineError(RuntimeError):
    """An engine invocation failed or violated the IPC contract."""


def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def engine_command() -> tuple[list[str], Path | None]:
    configured = os.environ.get("NETRA_ENGINE")
    if configured:
        executable = Path(configured).expanduser().resolve()
        if not executable.is_file():
            raise EngineError(f"NETRA_ENGINE no apunta a un archivo: {executable}")
        return [str(executable)], None

    package_bin = Path(__file__).resolve().parent / "bin"
    packaged_candidates = (
        package_bin / "netra-engine.exe",
        package_bin / "netra-engine",
    )
    for candidate in packaged_candidates:
        if candidate.is_file():
            return [str(candidate)], None

    root = project_root()
    candidates = (
        root / "engine" / "bin" / "netra-engine.exe",
        root / "engine" / "bin" / "netra-engine",
    )
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)], None

    installed = shutil.which("netra-engine")
    if installed:
        return [installed], None

    go = shutil.which("go")
    engine_root = root / "engine"
    if go and (engine_root / "go.mod").is_file():
        return [go, "run", "./cmd/netra-engine"], engine_root

    raise EngineError("No se encontró netra-engine ni un toolchain Go para ejecutarlo desde fuentes.")


def request(
    message_type: str,
    payload: dict[str, Any] | None = None,
    *,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    command, cwd = engine_command()
    envelope = {
        "protocol_version": "1.0",
        "id": str(uuid.uuid4()),
        "type": message_type,
        "payload": payload or {},
    }
    child_environment = _engine_environment()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        env=child_environment,
        creationflags=creationflags,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    events: list[dict[str, Any]] = []
    parse_error: str | None = None
    try:
        process.stdin.write(json.dumps(envelope, ensure_ascii=False) + "\n")
        process.stdin.close()
        for raw_line in process.stdout:
            if len(raw_line) > 4 * 1024 * 1024:
                parse_error = "El motor emitió un evento que supera 4 MiB."
                continue
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                _validate_event(event, envelope["id"])
            except (json.JSONDecodeError, EngineError) as exc:
                parse_error = f"El motor emitió NDJSON inválido: {exc}: {line[:200]}"
                continue
            events.append(event)
            if on_event:
                on_event(event)
        diagnostics = process.stderr.read().strip()
        return_code = process.wait()
    except KeyboardInterrupt:
        _stop_process(process, graceful=True)
        raise EngineError("Ejecución cancelada por el usuario.") from None
    except BaseException:
        _stop_process(process, graceful=False)
        raise
    if parse_error:
        raise EngineError(parse_error)
    if return_code != 0:
        message = diagnostics or _event_error(events) or f"salida {return_code}"
        raise EngineError(f"El motor falló: {message}")
    if not events:
        raise EngineError("El motor terminó sin emitir eventos.")
    failure = next((event for event in events if event.get("type") == "run.failed"), None)
    if failure:
        detail = failure.get("payload", {}).get("message", "error no especificado")
        raise EngineError(str(detail))
    return events


def _validate_event(event: Any, request_id: str) -> None:
    if not isinstance(event, dict):
        raise EngineError("el evento no es un objeto")
    if event.get("protocol_version") != "1.0":
        raise EngineError("versión de protocolo inesperada")
    if event.get("request_id") != request_id:
        raise EngineError("request_id inesperado")
    if not isinstance(event.get("type"), str) or not event["type"]:
        raise EngineError("tipo de evento ausente")
    if "payload" not in event:
        raise EngineError("payload de evento ausente")


def _stop_process(process: subprocess.Popen[str], *, graceful: bool) -> None:
    if process.poll() is not None:
        return
    if graceful:
        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGINT)
            process.wait(timeout=3)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=2)


def final_payload(events: list[dict[str, Any]], event_type: str) -> dict[str, Any]:
    for event in reversed(events):
        if event.get("type") == event_type:
            payload = event.get("payload")
            if isinstance(payload, dict):
                return payload
    raise EngineError(f"El motor no emitió el evento requerido: {event_type}")


def _event_error(events: list[dict[str, Any]]) -> str | None:
    for event in reversed(events):
        if event.get("type") == "run.failed":
            return str(event.get("payload", {}).get("message"))
    return None


def _engine_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("NETRA_SNMP_")
    }
    environment["NO_COLOR"] = os.environ.get("NO_COLOR", "")
    return environment
