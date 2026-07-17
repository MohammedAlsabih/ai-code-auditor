import argparse

from auditor import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditor", description="AI Code Auditor")
    p.add_argument("--version", action="version", version=f"ai-code-auditor {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
