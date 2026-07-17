from pathlib import Path

import pytest

import tree_sitter_c_sharp
import tree_sitter_java
import tree_sitter_python
import tree_sitter_typescript

from auditor.core import treesitter as _ts
from auditor.core.models import PackageInfo

_ts.register_language("python", tree_sitter_python.language())
_ts.register_language("java", tree_sitter_java.language())
_ts.register_language("csharp", tree_sitter_c_sharp.language())
_ts.register_language("typescript", tree_sitter_typescript.language_typescript())
_ts.register_language("tsx", tree_sitter_typescript.language_tsx())

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRegistry:
    """Deterministic in-memory registry for engine/E2E tests."""

    def __init__(self, ecosystem: str, known: dict[str, PackageInfo]):
        self.ecosystem = ecosystem
        self.known = {k.lower(): v for k, v in known.items()}
        self.calls: list[str] = []

    def lookup(self, name: str) -> PackageInfo:
        self.calls.append(name.lower())
        return self.known.get(name.lower(), PackageInfo(exists=False))


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
