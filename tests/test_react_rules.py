from pathlib import Path

from auditor.adapters.typescript.react_rules import (HookInConditional,
                                                     HookInNestedCallback,
                                                     HookOutsideComponent)
from auditor.core.models import SourceFile
from auditor.core.treesitter import parse_source


def _sf(code: str) -> SourceFile:
    sf = SourceFile(path=Path("C.tsx"), rel="C.tsx", language="tsx",
                    text=code.encode("utf-8"))
    parse_source(sf)
    return sf


GOOD = """
import {useState, useEffect} from 'react';
export function Widget({q}: {q: string}) {
  const [v, setV] = useState(0);
  useEffect(() => { console.log(q); }, [q]);
  return <div>{v}</div>;
}
"""


def test_clean_component_no_findings():
    sf = _sf(GOOD)
    for rule in (HookInConditional(), HookInNestedCallback(), HookOutsideComponent()):
        assert rule.check(sf) == [], rule.id


def test_r001_hook_in_if_and_loop_and_ternary():
    sf = _sf("""
export function Bad({flag}: {flag: boolean}) {
  if (flag) { const [a] = useState(1); }
  for (let i = 0; i < 2; i++) { useEffect(() => {}); }
  const v = flag ? useMemo(() => 1, []) : 0;
  return <p>{v}</p>;
}
""")
    fs = HookInConditional().check(sf)
    assert len(fs) == 3 and all(f.rule_id == "R001" for f in fs)


def test_r002_hook_inside_hook_callback():
    sf = _sf("""
export function Bad() {
  useEffect(() => { const [x] = useState(0); }, []);
  return null;
}
""")
    fs = HookInNestedCallback().check(sf)
    assert [f.rule_id for f in fs] == ["R002"]
    assert "useState" in fs[0].snippet


def test_r002_state_setter_in_callback_is_clean():
    sf = _sf("""
export function Fine() {
  const [v, setV] = useState(0);
  useEffect(() => { setV(1); }, []);
  return null;
}
""")
    assert HookInNestedCallback().check(sf) == []


def test_r003_hook_in_plain_function():
    sf = _sf("""
function loadData() {
  const [d] = useState(null);
  return d;
}
""")
    fs = HookOutsideComponent().check(sf)
    assert [f.rule_id for f in fs] == ["R003"]


def test_r003_hook_in_event_handler_arrow():
    sf = _sf("""
export function Btn() {
  return <button onClick={() => { const [v] = useState(0); }}>x</button>;
}
""")
    fs = HookOutsideComponent().check(sf)
    assert [f.rule_id for f in fs] == ["R003"]
    assert "anonymous callback" in fs[0].detail


def test_r003_memo_and_forwardref_wrapped_components_are_legal():
    for code in (
        "const Btn = memo(() => { const [v] = useState(0); return <b>{v}</b>; });",
        "const In = forwardRef((props, ref) => { const [v] = useState(0); return <input/>; });",
        "const B = React.memo(() => { const [v] = useState(0); return null; });",
    ):
        assert HookOutsideComponent().check(_sf(code)) == [], code


def test_r001_early_return_ignores_returns_inside_prior_callbacks():
    sf = _sf("""
export function C({x}: {x: boolean}) {
  if (x) { run(() => { return 1; }); }
  const items = list.filter(i => { return i > 1; });
  const [v] = useState(0);
  return <p>{v}</p>;
}
""")
    assert HookInConditional().check(sf) == []


def test_r001_logical_and_short_circuit():
    sf = _sf("""
export function C({flag}: {flag: boolean}) {
  const v = flag && useMemo(() => 1, []);
  return <p>{v}</p>;
}
""")
    assert [f.rule_id for f in HookInConditional().check(sf)] == ["R001"]


def test_r001_hook_after_early_return():
    sf = _sf("""
export function C({x}: {x: boolean}) {
  if (x) return null;
  const [v] = useState(0);
  return <p>{v}</p>;
}
""")
    fs = HookInConditional().check(sf)
    assert [f.rule_id for f in fs] == ["R001"]
    assert "early return" in fs[0].detail


def test_r003_allows_custom_hooks():
    sf = _sf("""
function useThing() {
  const [d] = useState(null);
  return d;
}
""")
    assert HookOutsideComponent().check(sf) == []
