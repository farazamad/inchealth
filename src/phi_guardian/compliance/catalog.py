"""Load and index the shared control catalog (compliance/controls.json)."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path


class ControlType(str, enum.Enum):
    AUTOMATED = "automated"   # verified by phi-scan against a Terraform plan
    RUNTIME = "runtime"       # enforced by a running platform component
    MANUAL = "manual"         # requires human attestation / process evidence


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    type: ControlType
    component: str
    mappings: dict[str, list[str]] = field(default_factory=dict)

    def requirements(self, framework: str) -> list[str]:
        return list(self.mappings.get(framework, []))


@dataclass
class Catalog:
    frameworks: dict[str, dict[str, str]]
    controls: list[Control]

    def __post_init__(self) -> None:
        self._by_id = {c.id: c for c in self.controls}

    def framework_keys(self) -> list[str]:
        return list(self.frameworks.keys())

    def framework_name(self, key: str) -> str:
        return self.frameworks.get(key, {}).get("name", key)

    def get(self, control_id: str) -> Control | None:
        return self._by_id.get(control_id)

    def controls_for_framework(self, framework: str) -> list[Control]:
        return [c for c in self.controls if framework in c.mappings]


def load_catalog(path: str | Path) -> Catalog:
    raw = json.loads(Path(path).read_text())
    controls = [
        Control(
            id=c["id"],
            title=c["title"],
            type=ControlType(c["type"]),
            component=c.get("component", ""),
            mappings={k: list(v) for k, v in c.get("mappings", {}).items()},
        )
        for c in raw.get("controls", [])
    ]
    return Catalog(frameworks=raw.get("frameworks", {}), controls=controls)


def default_catalog_path(start: str | Path | None = None) -> Path:
    """Search upward from ``start`` (or cwd) for compliance/controls.json."""
    here = Path(start or Path.cwd()).resolve()
    for base in [here, *here.parents]:
        candidate = base / "compliance" / "controls.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "could not locate compliance/controls.json; pass --catalog explicitly"
    )
