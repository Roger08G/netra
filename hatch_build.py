from __future__ import annotations

import platform
import sys
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel":
            return
        if sys.platform != "win32":
            raise RuntimeError("La distribución binaria 1.0.0 solo se construye en Windows.")
        architecture = platform.machine().lower()
        platform_tag = {
            "amd64": "win_amd64",
            "x86_64": "win_amd64",
            "arm64": "win_arm64",
            "aarch64": "win_arm64",
        }.get(architecture)
        if platform_tag is None:
            raise RuntimeError(f"Arquitectura Windows no soportada: {architecture}")
        build_data["pure_python"] = False
        build_data["tag"] = f"py3-none-{platform_tag}"
