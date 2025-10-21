"""Entry point for `python -m scanner`."""

from __future__ import annotations

from scanner import cli


def main(argv: list[str] | None = None) -> int:
    return cli.main(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
