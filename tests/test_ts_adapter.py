import json
from pathlib import Path

from auditor.adapters.typescript.adapter import TypeScriptAdapter
from auditor.core.models import Diagnostics, ImportRef
from auditor.core.treesitter import parse_source
from auditor.core.walk import collect_source_files


def _mk(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _prep(tmp_path, adapter):
    files = collect_source_files(tmp_path, adapter)
    for f in files:
        parse_source(f)
    adapter.prepare(tmp_path, files)
    return files


def test_detect_and_deps(tmp_path):
    a = TypeScriptAdapter()
    assert not a.detect(tmp_path)
    _mk(tmp_path, "package.json", json.dumps({
        "dependencies": {"react": "^19.0.0", "next": "^16.0.0", "internal-lib": "workspace:*"},
        "devDependencies": {"@types/node": "^24.0.0"},
    }))
    assert a.detect(tmp_path)
    deps = a.parse_dependencies(tmp_path)
    by = {d.name: d for d in deps}
    assert set(by) == {"react", "next", "internal-lib", "@types/node"}
    assert by["internal-lib"].skip_registry is True
    assert by["@types/node"].skip_registry is False


def test_npm_alias_spec_sets_registry_name(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({
        "dependencies": {"foo": "npm:bar@^1", "sco": "npm:@scope/pkg@^2",
                         "plain": "npm:baz"}}))
    by = {d.name: d for d in TypeScriptAdapter().parse_dependencies(tmp_path)}
    assert by["foo"].registry_name == "bar" and by["foo"].lookup_name == "bar"
    assert by["sco"].registry_name == "@scope/pkg"
    assert by["plain"].registry_name == "baz"


def test_import_extraction_and_locality(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({"dependencies": {"react": "*"}}))
    _mk(tmp_path, "tsconfig.json",
        '{\n  // jsonc comment\n  "compilerOptions": {"paths": {"@app/*": ["./src/*"]},},\n}')
    _mk(tmp_path, "src/main.ts", "\n".join([
        "import fs from 'fs';",
        "import path from 'node:path';",
        "import {x} from 'lodash';",
        "import type {T} from '@types/thing';",
        "import sub from '@scope/pkg/deep';",
        "import local from './util';",
        "import aliased from '@app/other';",
        "export {y} from 'exported-pkg';",
        "const z = require('required-pkg');",
        "const w = import('dynamic-pkg');",
        "import 'side-effect-pkg';",
    ]) + "\n")
    a = TypeScriptAdapter()
    files = _prep(tmp_path, a)
    imps = a.extract_imports(files)
    tops = {i.top_level for i in imps}
    assert {"fs", "node:path", "lodash", "@scope/pkg", "exported-pkg",
            "required-pkg", "dynamic-pkg", "side-effect-pkg"} <= tops
    assert not any(i.top_level in ("./util", "@app/other") for i in imps)  # locals excluded
    by = {i.top_level: i for i in imps}
    assert a.is_internal(by["fs"]) and a.is_internal(by["node:path"])
    assert not a.is_internal(by["lodash"])


def test_alias_import_is_internal(tmp_path):
    _mk(tmp_path, "package.json", "{}")
    _mk(tmp_path, "tsconfig.json",
        '{"compilerOptions": {"paths": {"@app/*": ["./src/*"]}}}')
    a = TypeScriptAdapter()
    _prep(tmp_path, a)
    assert a.is_internal(ImportRef("@app/other", "m.ts", 1, top_level="@app/other"))


def test_scoped_top_level_and_candidates(tmp_path):
    _mk(tmp_path, "package.json", "{}")
    a = TypeScriptAdapter()
    _prep(tmp_path, a)
    imp = ImportRef(module="@scope/pkg/deep", file="a.ts", line=1, top_level="@scope/pkg")
    assert a.registry_candidates(imp) == ["@scope/pkg"]


def test_frameworks_detection(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({"dependencies": {"react": "*", "next": "*"}}))
    _mk(tmp_path, "app/page.tsx", "export default function Page(){return null}")
    a = TypeScriptAdapter()
    deps = a.parse_dependencies(tmp_path)
    assert set(a.frameworks(tmp_path, deps)) == {"react", "next"}


def test_next_requires_router_dir(tmp_path):
    _mk(tmp_path, "package.json", json.dumps({"dependencies": {"react": "*", "next": "*"}}))
    a = TypeScriptAdapter()
    deps = a.parse_dependencies(tmp_path)
    assert a.frameworks(tmp_path, deps) == ["react"]     # no app/ or pages/


def test_file_language(tmp_path):
    a = TypeScriptAdapter()
    assert a.file_language(Path("x.tsx")) == "tsx"
    assert a.file_language(Path("x.jsx")) == "tsx"
    assert a.file_language(Path("x.ts")) == "typescript"
    assert a.file_language(Path("x.js")) == "typescript"


def test_scoped_unresolvable_hint_lives_in_adapter():
    a = TypeScriptAdapter()
    assert a.unresolvable_hint("@corp/secret") is not None
    assert a.unresolvable_hint("lodash") is None


def test_package_json_schema_tolerance(tmp_path):
    # non-dict document and non-dict group must not crash — and must be NOTED
    _mk(tmp_path, "package.json", '["not", "an", "object"]')
    diag = Diagnostics()
    assert TypeScriptAdapter().parse_dependencies(tmp_path, diag=diag) == []
    assert any("package.json" in n for n in diag.notes)

    root2 = tmp_path / "g"
    root2.mkdir()
    _mk(root2, "package.json", json.dumps({"dependencies": "oops"}))
    diag2 = Diagnostics()
    assert TypeScriptAdapter().parse_dependencies(root2, diag=diag2) == []
    assert any("dependencies" in n for n in diag2.notes)
    assert any(p.endswith("package.json") for p in diag2.manifest_incomplete)
    from auditor.core.scoring import verdict
    assert verdict({"red": 0, "yellow": 0}, 100,
                   {"manifest_incomplete": diag2.manifest_incomplete}) == "review"


def test_private_registry_reason_npmrc(tmp_path):
    _mk(tmp_path, "package.json", "{}")
    _mk(tmp_path, ".npmrc", "@corp:registry=https://npm.corp.example\n")
    a = TypeScriptAdapter()
    a.parse_dependencies(tmp_path)
    assert a.private_registry_reason(tmp_path) is not None


def test_ts_repo_e2e_hallucinations(fixtures_dir):
    from auditor.core.hallucination import audit_hallucinations
    from auditor.core.models import PackageInfo
    from tests.conftest import FakeRegistry

    root = fixtures_dir / "ts_repo"
    a = TypeScriptAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(root)
    a.prepare(root, files)
    reg = FakeRegistry("npm", {
        "react": PackageInfo(True, created="2013-05-24T00:00:00Z"),
        "next": PackageInfo(True, created="2016-10-05T00:00:00Z"),
        "@types/node": PackageInfo(True, created="2016-03-01T00:00:00Z"),
        "pg": PackageInfo(True, created="2010-10-25T00:00:00Z"),
    })
    findings = audit_hallucinations(a, root, files, declared, reg)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["H001", "H002", "H008"]   # left-pad-ai-super / pg / axios-retry-ai
    files_by_rule = {f.rule_id: f.file for f in findings}
    assert files_by_rule == {"H001": "package.json", "H002": "lib/db.ts", "H008": "lib/db.ts"}


def test_ts_repo_e2e_rules(fixtures_dir):
    root = fixtures_dir / "ts_repo"
    a = TypeScriptAdapter()
    files = collect_source_files(root, a)
    for f in files:
        parse_source(f)
    declared = a.parse_dependencies(root)
    a.prepare(root, files)
    frameworks = a.frameworks(root, declared)
    assert set(frameworks) == {"react", "next"}
    findings = []
    for rule in a.language_rules():
        if rule.frameworks and not set(rule.frameworks) & set(frameworks):
            continue
        for sf in files:
            findings += rule.check(sf)
    findings += a.project_rules(root, frameworks)
    ids = {f.rule_id for f in findings}
    # planted: R001 (conditional hook), R004 (no deps array), R006 (index key),
    # R007 (dynamic __html) in Widget.tsx; N001 in .env.local; N006 via the
    # graph for app/page.tsx (useState + onClick in a server path)
    assert {"R001", "R004", "R006", "R007", "N001", "N006"} <= ids
    assert "N003" not in ids               # graph supersedes the per-file fallback
    n001 = [f for f in findings if f.rule_id == "N001"]
    assert any(f.file == ".env.local" for f in n001)
    assert all("sk-fixture-not-real" not in f.snippet + f.detail for f in n001)
