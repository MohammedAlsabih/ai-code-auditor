from auditor.registries.cache import Cache


def test_set_get_roundtrip(tmp_path):
    c = Cache(tmp_path / "c.json")
    c.set("pypi:requests", {"exists": True}, ttl_seconds=60)
    assert c.get("pypi:requests") == {"exists": True}


def test_expiry(tmp_path):
    c = Cache(tmp_path / "c.json")
    c.set("k", {"v": 1}, ttl_seconds=-1)
    assert c.get("k") is None


def test_persists_across_instances(tmp_path):
    Cache(tmp_path / "c.json").set("k", {"v": 2}, ttl_seconds=60)
    assert Cache(tmp_path / "c.json").get("k") == {"v": 2}


def test_corrupt_cache_structures_are_cold_not_crash(tmp_path):
    # valid JSON, wrong structure — must load as an empty cache, never raise
    for content in ("[]", '{"x": null}', '{"x": "oops"}', '{"x": {"value": {}}}',
                    '{"x": {"expires": "soon", "value": {}}}'):
        p = tmp_path / "c.json"
        p.write_text(content, encoding="utf-8")
        c = Cache(p)                      # no crash on load
        assert c.get("x") is None         # malformed entry ignored
        c.set("y", {"ok": True}, 60)      # still usable
        assert c.get("y") == {"ok": True}


def test_save_failure_does_not_raise_and_leaves_no_tmp(tmp_path, monkeypatch):
    import auditor.registries.cache as cachemod
    c = Cache(tmp_path / "c.json")

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(cachemod.os, "replace", boom)
    c.set("k", {"v": 1}, 60)              # save fails internally, must NOT raise
    assert c.get("k") == {"v": 1}         # in-memory result preserved
    tmps = list(tmp_path.glob("*.tmp"))
    assert tmps == []                     # temp file cleaned up
