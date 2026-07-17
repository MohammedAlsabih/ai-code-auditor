from pathlib import Path

import tree_sitter_python

from auditor.core import treesitter as ts
from auditor.core.models import SourceFile

SNIPPETS = {
    "python": (b"import os\nfrom x import y\n", "[(import_statement) (import_from_statement)] @imp", 2),
    "java": (b"import com.foo.Bar;\nclass A {}\n", "(import_declaration) @imp", 1),
    "csharp": (b"using System.Text;\nclass A {}\n", "(using_directive) @imp", 1),
    "typescript": (b"import {x} from 'lodash';\n", "(import_statement) @imp", 1),
    "tsx": (b"import React from 'react';\nexport const C = () => <div>hi</div>;\n", "(import_statement) @imp", 1),
}


def test_all_five_grammars_parse_and_query():
    for lang, (src, query, expected) in SNIPPETS.items():
        sf = SourceFile(path=Path(f"x.{lang}"), rel=f"x.{lang}", language=lang, text=src)
        ts.parse_source(sf)
        assert sf.tree is not None and not sf.tree.root_node.has_error, lang
        caps = ts.captures(lang, sf.tree.root_node, query)
        assert len(caps.get("imp", [])) == expected, lang


def test_node_text_and_line():
    sf = SourceFile(path=Path("a.py"), rel="a.py", language="python", text=b"import os\n")
    ts.parse_source(sf)
    node = ts.captures("python", sf.tree.root_node, "(import_statement) @i")["i"][0]
    assert ts.node_text(node) == "import os"
    assert ts.line_of(node) == 1


def test_registry_is_idempotent_and_unknown_name_raises():
    ts.register_language("python", tree_sitter_python.language())  # re-register: no-op
    assert ts.get_language("python") is ts.get_language("python")
    import pytest as _pytest
    with _pytest.raises(ValueError):
        ts.get_language("cobol")
