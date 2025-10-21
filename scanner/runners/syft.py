"""Helpers for interpreting Syft-emitted metadata."""

from __future__ import annotations

from typing import Dict

OS_PACKAGE_HINTS = {
    "apk",
    "apkdb",
    "dpkg",
    "deb",
    "debdb",
    "rpm",
    "rpmdb",
    "oci",
    "os",
    "windows",
}


def infer_component_type(raw: Dict[str, object], props: Dict[str, object]) -> str:
    type_hint = str(raw.get("type") or raw.get("Type") or "").lower()
    prop_type = str(props.get("syft:package:type") or props.get("Type") or "").lower()
    metadata_type = str(props.get("syft:package:metadata-type") or "").lower()
    if any(hint in OS_PACKAGE_HINTS for hint in (type_hint, prop_type, metadata_type)):
        return "os"
    scope = str(raw.get("scope") or "").lower()
    if scope in {"required", "runtime"} and metadata_type:
        return "app"
    return "app"


def infer_layer(raw: Dict[str, object], props: Dict[str, object], component_type: str) -> str:
    if component_type == "os":
        return "base"
    layer_hint = str(props.get("layer") or props.get("syft:layerID") or raw.get("layer") or "").lower()
    if layer_hint and any(token in layer_hint for token in ("base", "stage", "rootfs")):
        return "base"
    return "app"


def extract_package_path(props: Dict[str, object]) -> str | None:
    for key in ("syft:artifact:file", "syft:file:path", "package-path", "PrimaryLocation"):
        if props.get(key):
            return str(props[key])
    return None
