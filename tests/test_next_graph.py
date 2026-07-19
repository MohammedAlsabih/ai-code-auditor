from pathlib import Path

from auditor.adapters.typescript.next_graph import analyze
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(rel: str, code: str) -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def _run(*files, alias_map=()):
    return analyze(list(files), alias_map=alias_map)[:2]   # (findings, notes)


def test_hooky_via_server_path_is_flagged_outside_app():
    page = _sf("app/page.tsx", "import Hooky from '../components/Hooky';\n"
               "export default function Page(){ return <Hooky/>; }")
    hooky = _sf("components/Hooky.tsx",
                "import {useState} from 'react';\n"
                "export default function Hooky(){ const [v] = useState(0); return <b>{v}</b>; }")
    findings, _ = _run(page, hooky)
    assert any(f.rule_id == "N006" and f.file == "components/Hooky.tsx" for f in findings)


def test_leaf_inherited_client_is_clean_but_gets_client_checks():
    page = _sf("app/page.tsx", "import P from '../components/ClientParent';\n"
               "export default function Page(){ return <P/>; }")
    parent = _sf("components/ClientParent.tsx", '"use client";\n'
                 "import Leaf from './Leaf';\n"
                 "export default function P(){ return <Leaf/>; }")
    leaf = _sf("components/Leaf.tsx",
               "import {useState} from 'react';\n"
               "const k = process.env.DATABASE_URL;\n"
               "export default function Leaf(){ const [v] = useState(0); return <i>{v}</i>; }")
    findings, _ = _run(page, parent, leaf)
    leaf_rules = {f.rule_id for f in findings if f.file == "components/Leaf.tsx"}
    assert "N006" not in leaf_rules        # inherited client => hooks are LEGAL
    assert "N002" in leaf_rules            # but private env read is not


def test_inheritance_inside_app_dir_not_the_old_prefix_shortcut():
    page = _sf("app/page.tsx", "import P from './parent';\n"
               "export default function Page(){ return <P/>; }")
    parent = _sf("app/parent.tsx", '"use client";\n'
                 "import Inner from './inner';\n"
                 "export default function P(){ return <Inner/>; }")
    inner = _sf("app/inner.tsx",
                "import {useState} from 'react';\n"
                "export default function I(){ const [v] = useState(0); return <s>{v}</s>; }")
    findings, _ = _run(page, parent, inner)
    assert not any(f.rule_id == "N006" and f.file == "app/inner.tsx" for f in findings)


def test_shared_file_server_violation_stands_despite_client_path():
    p1 = _sf("app/page.tsx", "import S from '../components/Shared';\n"
             "export default function A(){ return <S/>; }")
    p2 = _sf("app/layout.tsx", "import C from '../components/ClientSide';\n"
             "export default function L(){ return <C/>; }")
    client = _sf("components/ClientSide.tsx", '"use client";\n'
                 "import S from './Shared';\n"
                 "export default function C(){ return <S/>; }")
    shared = _sf("components/Shared.tsx",
                 "import {useState} from 'react';\n"
                 "export default function S(){ const [v] = useState(0); return <u>{v}</u>; }")
    findings, _ = _run(p1, p2, client, shared)
    assert any(f.rule_id == "N006" and f.file == "components/Shared.tsx" for f in findings)


def test_type_only_edges_are_not_boundary_edges():
    page = _sf("app/page.tsx", "import type {T} from '../components/Types';\n"
               "export default function Page(){ return null; }")
    types = _sf("components/Types.tsx",
                "import {useState} from 'react';\n"
                "export function useT(){ return useState(0); }\nexport type T = number;")
    findings, _ = _run(page, types)
    assert not any(f.file == "components/Types.tsx" for f in findings)


def test_cycle_terminates_and_orphan_is_noted():
    a = _sf("app/page.tsx", "import B from './b';\nexport default function A(){ return <B/>; }")
    b = _sf("app/b.tsx", "import A from './page';\nexport default function B(){ return null; }")
    orphan = _sf("app/orphan.tsx", "export default function O(){ return null; }")
    findings, notes = _run(a, b, orphan)
    assert any("orphan" in n for n in notes)


def test_src_app_layout_and_alias_target_resolution():
    # src/app entries + "@/*":["./src/*"] must resolve @/components/Hooky to
    # src/components/Hooky (NOT components/Hooky)
    page = _sf("src/app/page.tsx", "import Hooky from '@/components/Hooky';\n"
               "export default function Page(){ return <Hooky/>; }")
    hooky = _sf("src/components/Hooky.tsx",
                "import {useState} from 'react';\n"
                "export default function Hooky(){ const [v] = useState(0); return <b>{v}</b>; }")
    findings, _ = _run(page, hooky, alias_map=(("@", "src"),))
    assert any(f.rule_id == "N006" and f.file == "src/components/Hooky.tsx" for f in findings)


def test_orphan_with_hook_is_flagged_not_dropped():
    # orphan app/ file with a hook and no directive must still be caught — the
    # graph analyzes it standalone as server default
    entry = _sf("app/page.tsx", "export default function P(){ return null; }")
    orphan = _sf("app/widget.tsx", "import {useState} from 'react';\n"
                 "export function W(){ const [v] = useState(0); return <i>{v}</i>; }")
    findings, notes = _run(entry, orphan)
    assert any(f.rule_id == "N006" and f.file == "app/widget.tsx" for f in findings)
    assert any("orphan" in n for n in notes)


def test_window_location_in_server_path_is_flagged():
    # window.location is a member_expression; the object side must count as use
    page = _sf("app/page.tsx", "import S from '../components/Srv';\n"
               "export default function P(){ return <S/>; }")
    srv = _sf("components/Srv.tsx",
              "export function S(){ const u = window.location.href; return <a>{u}</a>; }")
    findings, _ = _run(page, srv)
    assert any(f.rule_id == "N006" and f.file == "components/Srv.tsx"
               and "window" in f.detail for f in findings)


def test_new_conventions_are_entries():
    from auditor.adapters.typescript.next_graph import _is_entry
    for stem in ("global-not-found", "forbidden", "unauthorized"):
        assert _is_entry(f"app/{stem}.tsx"), stem
    assert _is_entry("src/app/page.tsx")
    assert not _is_entry("app/middleware.ts")   # documented exclusion
