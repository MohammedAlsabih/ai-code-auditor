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
