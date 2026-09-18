from __future__ import annotations

import sys
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("uso: verify_wheel.py WHEEL", file=sys.stderr)
        return 2
    wheel = Path(sys.argv[1]).resolve()
    if "-win_" not in wheel.name:
        print(f"wheel sin etiqueta Windows: {wheel.name}", file=sys.stderr)
        return 1
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        required_suffixes = {
            "netra/bin/netra-engine.exe",
            "netra/schemas/run-artifact.schema.json",
            "netra/schemas/managed-topology.schema.json",
            "netra/schemas/snmpv3-config.schema.json",
            "netra-1.0.0.dist-info/METADATA",
            "netra-1.0.0.dist-info/WHEEL",
            "netra-1.0.0.dist-info/RECORD",
        }
        missing = sorted(required_suffixes - names)
        if missing:
            print(f"faltan entradas en el wheel: {', '.join(missing)}", file=sys.stderr)
            return 1
        metadata = archive.read("netra-1.0.0.dist-info/METADATA").decode("utf-8")
        wheel_metadata = archive.read("netra-1.0.0.dist-info/WHEEL").decode("utf-8")
        if "Version: 1.0.0\n" not in metadata.replace("\r\n", "\n"):
            print("la metadata no declara 1.0.0", file=sys.stderr)
            return 1
        if "Root-Is-Purelib: false" not in wheel_metadata:
            print("el wheel se marcó incorrectamente como purelib", file=sys.stderr)
            return 1
    print(f"wheel verificado: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
