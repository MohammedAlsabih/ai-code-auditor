from __future__ import annotations

from tree_sitter import Language, Parser, Query, QueryCursor

from auditor.core.models import SourceFile

_LANGS: dict[str, Language] = {}


def register_language(name: str, grammar_ptr: object) -> None:
    """Append-only + idempotent by design: first registration of a name wins,
    re-registering the same name is a silent no-op (adapters may be constructed
    many times). Language names are coordinated in the adapters — one owner per
    name. The registry is module-level CACHED state, never mutated after set;
    tests that need isolation call reset_registry()."""
    if name not in _LANGS:
        _LANGS[name] = Language(grammar_ptr)


def reset_registry() -> None:
    _LANGS.clear()


def register_adapters(adapters) -> None:
    for adapter in adapters:
        for name, ptr in adapter.grammars().items():
            register_language(name, ptr)


def get_language(name: str) -> Language:
    if name not in _LANGS:
        raise ValueError(
            f"tree-sitter language '{name}' is not registered — "
            "call register_adapters(default_adapters()) first")
    return _LANGS[name]


def get_parser(name: str) -> Parser:
    return Parser(get_language(name))


def parse_source(sf: SourceFile) -> None:
    if sf.tree is None:
        sf.tree = get_parser(sf.language).parse(sf.text)


def captures(lang_name: str, node, query_src: str) -> dict[str, list]:
    query = Query(get_language(lang_name), query_src)
    return QueryCursor(query).captures(node)


def node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def line_of(node) -> int:
    return node.start_point[0] + 1
