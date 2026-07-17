from pathlib import Path

from auditor.adapters.typescript.next_rules import (NEXT_RULES,
                                                    AsyncClientComponent,
                                                    ClientApiInServerComponent,
                                                    PrivateEnvInClient,
                                                    PublicEnvSecret,
                                                    ServerImportInClient,
                                                    scan_env_files)
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str, rel: str = "app/page.tsx") -> SourceFile:
    sf = SourceFile(path=Path(rel), rel=rel, language="tsx", text=code.encode("utf-8"))
    parse_source(sf)
    return sf


def test_n001_public_secret_in_code():
    sf = _sf("const k = process.env.NEXT_PUBLIC_API_SECRET;")
    assert [f.rule_id for f in PublicEnvSecret().check(sf)] == ["N001"]


def test_n001_publishable_key_is_fine():
    sf = _sf("const k = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;")
    assert PublicEnvSecret().check(sf) == []


def test_n001_env_file_scan(tmp_path):
    (tmp_path / ".env.local").write_text(
        "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE=abc123\nNEXT_PUBLIC_APP_NAME=demo\n",
        encoding="utf-8")
    fs = scan_env_files(tmp_path)
    assert [f.rule_id for f in fs] == ["N001"] and ".env.local" in fs[0].file


def test_n001_env_file_never_echoes_the_value(tmp_path):
    (tmp_path / ".env").write_text(
        "NEXT_PUBLIC_API_SECRET=super-inert-value\n", encoding="utf-8")
    fs = scan_env_files(tmp_path)
    assert fs and all("super-inert-value" not in (f.snippet + f.detail) for f in fs)


def test_n002_private_env_in_client_file():
    sf = _sf('"use client";\nconst k = process.env.DATABASE_URL;\n')
    assert [f.rule_id for f in PrivateEnvInClient().check(sf)] == ["N002"]
    server = _sf("const k = process.env.DATABASE_URL;")  # no directive => server, fine
    assert PrivateEnvInClient().check(server) == []


def test_n003_hooks_in_server_component():
    sf = _sf("import {useState} from 'react';\n"
             "export default function Page() {\n"
             "  const [v] = useState(0);\n"
             "  return <button onClick={() => alert(v)}>x</button>;\n"
             "}\n")
    ids = [f.rule_id for f in ClientApiInServerComponent().check(sf)]
    assert ids.count("N003") == 2  # useState + onClick


def test_n003_ignores_files_outside_app_dir():
    sf = _sf("const v = useState(0);", rel="components/Widget.tsx")
    assert ClientApiInServerComponent().check(sf) == []


def test_n004_server_import_in_client():
    sf = _sf('"use client";\nimport fs from "fs";\nimport {cookies} from "next/headers";\n',
             rel="components/W.tsx")
    assert [f.rule_id for f in ServerImportInClient().check(sf)] == ["N004", "N004"]


def test_n005_async_client_component():
    sf = _sf('"use client";\nexport default async function Page() { return <div/>; }\n',
             rel="components/P.tsx")
    assert [f.rule_id for f in AsyncClientComponent().check(sf)] == ["N005"]


def test_next_rules_registry():
    assert len(NEXT_RULES) == 5
