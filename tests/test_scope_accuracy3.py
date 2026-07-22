"""W2-B2.8A final closing round: ReferenceOutputAssembly child metadata,
diamond graph merge, and total ConfigError hygiene."""
import pytest

from auditor.config import ConfigError, load_config
from auditor.core.models import Diagnostics, ImportRef


def _dotnet():
    from auditor.adapters.dotnet.adapter import DotnetAdapter
    return DotnetAdapter()


def _imp(module):
    return ImportRef(module=module, file="x", line=1, top_level=module)


def _proj(base, rel, body="", sdk="Microsoft.NET.Sdk"):
    d = base / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{d.name}.csproj").write_text(
        f'<Project Sdk="{sdk}">\n<PropertyGroup>'
        "<TargetFramework>net8.0</TargetFramework></PropertyGroup>\n"
        f"{body}\n</Project>", encoding="utf-8")
    return d


_ASP = ('<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />'
        "</ItemGroup>")


def _internal(ad, module):
    ad._own_namespaces = ()
    ad._old_tfm = False
    return ad.is_internal(_imp(module))


# ── 1: ReferenceOutputAssembly as child metadata ─────────────────────────────

def test_roa_child_metadata_false_blocks_inheritance(tmp_path):
    _proj(tmp_path, "B", _ASP)
    a = _proj(tmp_path, "A",
              '<ItemGroup><ProjectReference Include="../B/B.csproj">'
              "<ReferenceOutputAssembly>false</ReferenceOutputAssembly>"
              "</ProjectReference></ItemGroup>")
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert not _internal(ad, "Microsoft.AspNetCore.Builder")


def test_roa_child_metadata_dynamic_is_possible(tmp_path):
    _proj(tmp_path, "B", _ASP)
    a = _proj(tmp_path, "A",
              '<ItemGroup><ProjectReference Include="../B/B.csproj">'
              "<ReferenceOutputAssembly>$(KeepRef)</ReferenceOutputAssembly>"
              "</ProjectReference></ItemGroup>")
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    ad.parse_dependencies(a, diag=diag)
    # possible: internal (no definitive H002) + incomplete with a note
    assert _internal(ad, "Microsoft.AspNetCore.Builder")
    assert "Microsoft.AspNetCore" in ad._fw_provides_possible
    assert diag.manifest_incomplete


def test_roa_attribute_false_still_blocks(tmp_path):
    _proj(tmp_path, "B", _ASP)
    a = _proj(tmp_path, "A",
              '<ItemGroup><ProjectReference Include="../B/B.csproj" '
              'ReferenceOutputAssembly="false" /></ItemGroup>')
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert not _internal(ad, "Microsoft.AspNetCore.Builder")


# ── 2: diamond graph merge ────────────────────────────────────────────────────

def _diamond(tmp_path, first_edge_conditional: bool):
    """A -> B -> D and A -> C -> D where exactly ONE A-edge is conditional.
    The order of the two edges inside A flips with the flag."""
    _proj(tmp_path, "D", _ASP)
    _proj(tmp_path, "B",
          '<ItemGroup><ProjectReference Include="../D/D.csproj" /></ItemGroup>')
    _proj(tmp_path, "C",
          '<ItemGroup><ProjectReference Include="../D/D.csproj" /></ItemGroup>')
    cond = ("<ItemGroup Condition=\"'$(X)'=='1'\">"
            '<ProjectReference Include="../B/B.csproj" /></ItemGroup>')
    plain = ('<ItemGroup><ProjectReference Include="../C/C.csproj" />'
             "</ItemGroup>")
    body = (cond + plain) if first_edge_conditional else (plain + cond)
    return _proj(tmp_path, "A", body)


@pytest.mark.parametrize("conditional_first", [True, False])
def test_diamond_definite_path_wins(tmp_path, conditional_first):
    a = _diamond(tmp_path, conditional_first)
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    diag = Diagnostics()
    ad.parse_dependencies(a, diag=diag)
    # ONE definite chain exists (A->C->D): the framework is DEFINITE and the
    # manifest is NOT flagged incomplete, regardless of edge order
    assert "Microsoft.AspNetCore" in ad._fw_provides_definite
    assert "Microsoft.AspNetCore" not in ad._fw_provides_possible
    assert not diag.manifest_incomplete
    assert _internal(ad, "Microsoft.AspNetCore.Builder")


def test_cycle_still_terminates_after_stack_change(tmp_path):
    _proj(tmp_path, "B", _ASP +
          '<ItemGroup><ProjectReference Include="../A/A.csproj" /></ItemGroup>')
    a = _proj(tmp_path, "A",
              '<ItemGroup><ProjectReference Include="../B/B.csproj" /></ItemGroup>')
    ad = _dotnet()
    ad.set_repo_root(tmp_path)
    ad.parse_dependencies(a, diag=Diagnostics())
    assert _internal(ad, "Microsoft.AspNetCore.Builder")


# ── 3: ConfigError hygiene, всех paths ────────────────────────────────────────

_SECRET = "C:/Users/private/SECRET"


def _assert_clean(msg):
    for frag in ("SECRET", "private", "Users", "C:/"):
        assert frag not in msg, msg


def test_schema_version_value_never_echoed(tmp_path):
    (tmp_path / ".auditor.toml").write_text(
        f'schema_version = "{_SECRET}"\n', encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    _assert_clean(msg)
    assert "unsupported schema_version (expected 1 or 2)" in msg


def test_unknown_ecosystem_key_never_echoed(tmp_path):
    (tmp_path / ".auditor.toml").write_text(
        f'schema_version = 1\n[runtime_builtins]\n"{_SECRET}" = ["x"]\n',
        encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    _assert_clean(msg)
    assert "unsupported ecosystem" in msg
    assert "npm" in msg                       # KNOWN names are listed


def test_unknown_top_level_key_never_echoed(tmp_path):
    (tmp_path / ".auditor.toml").write_text(
        f'schema_version = 1\n"{_SECRET}" = true\n', encoding="utf-8")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    msg = str(ei.value)
    _assert_clean(msg)
    assert "1 unknown key(s)" in msg
    assert "exclude_paths" in msg             # legal names only


def test_surrogate_in_key_or_value_no_crash(tmp_path):
    bad = "k\ud800ey"
    # write with surrogatepass so the FILE itself carries the lone surrogate
    raw = f'schema_version = 1\n"{bad}" = true\n'.encode("utf-8", "surrogatepass")
    (tmp_path / ".auditor.toml").write_bytes(raw)
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)                 # invalid TOML/UTF-8 or unknown key
    msg = str(ei.value)
    assert "\ud800" not in msg
