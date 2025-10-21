"""Utility functions for S3 interactions (optional)."""

from __future__ import annotations

import json
import logging
import pathlib
from typing import Any, Dict, Optional

try:
    import boto3  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    boto3 = None

_LOG = logging.getLogger(__name__)


def upload_json(bucket: str, key: str, payload: Dict[str, Any], client: Optional[Any] = None) -> None:
    serialized = json.dumps(payload).encode("utf-8")
    upload_bytes(bucket, key, serialized, client)


def upload_bytes(bucket: str, key: str, data: bytes, client: Optional[Any] = None) -> None:
    client = client or _client()
    if not client:
        _LOG.warning("boto3 not available; skipping upload for s3://%s/%s", bucket, key)
        return
    client.put_object(Bucket=bucket, Key=key, Body=data)


def download_file(bucket: str, key: str, destination: pathlib.Path, client: Optional[Any] = None) -> None:
    client = client or _client()
    if not client:
        raise RuntimeError("boto3 required for download")
    destination.parent.mkdir(parents=True, exist_ok=True)
    client.download_file(Bucket=bucket, Key=key, Filename=str(destination))


def _client() -> Any:
    if boto3 is None:
        return None
    return boto3.client("s3")
