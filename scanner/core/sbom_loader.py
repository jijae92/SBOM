"""SBOM loading helpers for CycloneDX and SPDX documents."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from scanner.runners import syft as syft_helpers


@dataclass(frozen=True)
class Component:
    """Normalized view of a software component discovered in an SBOM."""

    purl: Optional[str]
    name: str
    version: Optional[str]
    component_type: str  # "os" | "app"
    layer: str  # "base" | "app"
    package_path: Optional[str]
    raw: Dict[str, object]

    def key(self) -> Tuple[Optional[str], str, Optional[str]]:
        return (self.purl, self.name.lower(), self.version)


class ComponentIndex:
    """Lookup structure for components keyed by purl or name/version."""

    def __init__(self, components: Iterable[Component]) -> None:
        self._by_purl: Dict[str, Component] = {}
        self._by_name_version: Dict[Tuple[str, Optional[str]], Component] = {}
        for component in components:
            if component.purl:
                self._by_purl.setdefault(component.purl, component)
            key = (component.name.lower(), component.version)
            self._by_name_version.setdefault(key, component)

    def lookup(self, purl: Optional[str], name: Optional[str], version: Optional[str]) -> Optional[Component]:
        if purl and purl in self._by_purl:
            return self._by_purl[purl]
        if name:
            key = (name.lower(), version)
            if key in self._by_name_version:
                return self._by_name_version[key]
        return None

    def __len__(self) -> int:
        return len(self._by_name_version)


SUPPORTED_FORMATS = {"cyclonedx-json", "spdx-json"}


def load_directory(sbom_dir: pathlib.Path) -> ComponentIndex:
    """Load all SBOMs within *sbom_dir* and return a component index."""

    if not sbom_dir.exists():
        return ComponentIndex([])
    components: List[Component] = []
    for path in sorted(sbom_dir.glob("*.json")):
        components.extend(load_sbom(path))
    return ComponentIndex(components)


def load_sbom(path: pathlib.Path) -> List[Component]:
    data = json.loads(path.read_text())
    fmt = detect_format(data)
    if fmt == "cyclonedx-json":
        return _from_cyclonedx(data)
    if fmt == "spdx-json":
        return _from_spdx(data)
    raise ValueError(f"Unsupported SBOM format: {fmt}")


def detect_format(data: Dict[str, object]) -> str:
    if "spdxVersion" in data:
        return "spdx-json"
    if str(data.get("bomFormat", "")).lower() == "cyclonedx":
        return "cyclonedx-json"
    raise ValueError("Unsupported SBOM document; expected CycloneDX or SPDX JSON")


def _from_cyclonedx(data: Dict[str, object]) -> List[Component]:
    components_raw = data.get("components") or []
    components: List[Component] = []
    for raw in components_raw:
        if not isinstance(raw, dict):
            continue
        props = _properties_to_dict(raw.get("properties"), cast_keys=True)
        purl = raw.get("purl") or props.get("cdx:purl")  # alternate key
        name = str(raw.get("name") or props.get("Name") or "unknown")
        version = raw.get("version") or props.get("Version")
        component_type = syft_helpers.infer_component_type(raw, props)
        layer = syft_helpers.infer_layer(raw, props, component_type)
        package_path = syft_helpers.extract_package_path(props)
        components.append(
            Component(
                purl=str(purl) if purl else None,
                name=name,
                version=str(version) if version else None,
                component_type=component_type,
                layer=layer,
                package_path=str(package_path) if package_path else None,
                raw=raw,
            )
        )
    return components


def _from_spdx(data: Dict[str, object]) -> List[Component]:
    packages = data.get("packages") or []
    components: List[Component] = []
    for raw in packages:
        if not isinstance(raw, dict):
            continue
        external_refs = raw.get("externalRefs") or []
        props = _spdx_refs_to_properties(external_refs)
        purl = props.get("purl") or raw.get("purl")
        name = str(raw.get("name") or "unknown")
        version = raw.get("versionInfo") or props.get("version")
        component_type = syft_helpers.infer_component_type(raw, props)
        layer = syft_helpers.infer_layer(raw, props, component_type)
        package_path = raw.get("downloadLocation") or props.get("package-path")
        components.append(
            Component(
                purl=str(purl) if purl else None,
                name=name,
                version=str(version) if version else None,
                component_type=component_type,
                layer=layer,
                package_path=str(package_path) if package_path else None,
                raw=raw,
            )
        )
    return components


def _properties_to_dict(properties: object, cast_keys: bool = False) -> Dict[str, object]:
    result: Dict[str, object] = {}
    if isinstance(properties, list):
        for entry in properties:
            if isinstance(entry, dict):
                key = entry.get("name") if cast_keys else entry.get("Name") or entry.get("name")
                if key:
                    result[str(key)] = entry.get("value") or entry.get("Value")
    return result


def _spdx_refs_to_properties(external_refs: object) -> Dict[str, object]:
    result: Dict[str, object] = {}
    if isinstance(external_refs, list):
        for ref in external_refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceType") == "purl":
                result["purl"] = ref.get("referenceLocator")
            elif ref.get("referenceType") == "package-path":
                result["package-path"] = ref.get("referenceLocator")
            elif ref.get("referenceType") == "distribution" and ref.get("referenceLocator"):
                result["downloadLocation"] = ref.get("referenceLocator")
    return result
