"""Exact-byte reuse never substitutes for a fresh verified file snapshot."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import copy
import os

import pytest

from browser_core import personas
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from test_multi_identity_ops import _seed


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch):
    monkeypatch.setattr(personas, "_VALIDATED_PERSONA_BYTES", OrderedDict())
    monkeypatch.setattr(personas, "_VALIDATED_PERSONA_BYTES_SIZE", 0)


def test_hit_reuses_validation_but_reads_current_bytes(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=1)
    # Seeding verifies each newly published persona, warming the byte cache.
    personas._VALIDATED_PERSONA_BYTES.clear()
    monkeypatch.setattr(personas, "_VALIDATED_PERSONA_BYTES_SIZE", 0)
    validations, reads = [], []
    validate, read = personas.validate_persona, personas.read_bounded_control_snapshot_result
    def counted_validate(document):
        validations.append(True)
        return validate(document)
    def counted_read(*args, **kwargs):
        reads.append(True)
        return read(*args, **kwargs)
    monkeypatch.setattr(personas, "validate_persona", counted_validate)
    monkeypatch.setattr(personas, "read_bounded_control_snapshot_result", counted_read)
    first = personas.load_persona(tmp_path, ids[0])
    second = personas.load_persona(tmp_path, ids[0])
    assert first == second and first is not second
    # Each load reads once for validation and once to rebind saved bytes.
    assert len(validations) == 1 and len(reads) == 4
    second["device"]["viewport"]["width"] = 7
    assert personas.load_persona(tmp_path, ids[0])["device"]["viewport"]["width"] == 1280


def test_same_metadata_rewrite_misses_validation_cache(tmp_path):
    ids = _seed(tmp_path, count=1)
    old = personas.load_persona(tmp_path, ids[0])
    path = tmp_path / "personas" / "catalog" / f"{ids[0]}.json"
    metadata = path.stat()
    changed = copy.deepcopy(old)
    changed["name"] = "X" + changed["name"][1:]
    changed["integrity_sha256"] = personas.persona_digest(changed)
    body = canonical_json_bytes(changed)
    assert len(body) == metadata.st_size
    path.write_bytes(body)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert personas.load_persona(tmp_path, ids[0]) == changed
    assert old["name"] != changed["name"]
    path.write_bytes(body.replace(b'"X', b'"Y', 1))
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    with pytest.raises(ContractError, match="valid managed document"):
        personas.load_persona(tmp_path, ids[0])


def test_warm_bytes_do_not_authorize_hard_link(tmp_path):
    ids = _seed(tmp_path, count=1)
    personas.load_persona(tmp_path, ids[0])
    path = tmp_path / "personas" / "catalog" / f"{ids[0]}.json"
    alias = tmp_path / "outside-alias"
    os.link(path, alias)
    with pytest.raises(ContractError, match="hard links"):
        personas.load_persona(tmp_path, ids[0])
    assert alias.read_bytes() == path.read_bytes()


def test_byte_budget_eviction_requires_validation_again(tmp_path, monkeypatch):
    ids = _seed(tmp_path, count=2)
    personas._VALIDATED_PERSONA_BYTES.clear()
    monkeypatch.setattr(personas, "_VALIDATED_PERSONA_BYTES_SIZE", 0)
    size = (tmp_path / "personas" / "catalog" / f"{ids[0]}.json").stat().st_size
    monkeypatch.setattr(personas, "_VALIDATED_PERSONA_CACHE_BYTES", size)
    validations = []
    original = personas.validate_persona
    def counted(document):
        validations.append(document["id"])
        return original(document)
    monkeypatch.setattr(personas, "validate_persona", counted)
    for persona_id in [ids[0], ids[1], ids[0]]:
        personas.load_persona(tmp_path, persona_id)
    assert validations == [ids[0], ids[1], ids[0]]
    assert personas._VALIDATED_PERSONA_BYTES_SIZE <= size


def test_parallel_callers_get_independent_documents(tmp_path):
    ids = _seed(tmp_path, count=1)
    original = personas.load_persona(tmp_path, ids[0])
    def load_and_mutate(index):
        doc = personas.load_persona(tmp_path, ids[0])
        assert doc == original
        doc["device"]["viewport"]["width"] = index + 1
        return doc
    with ThreadPoolExecutor(max_workers=8) as pool:
        documents = list(pool.map(load_and_mutate, range(32)))
    assert len({id(doc["device"]) for doc in documents}) == 32
    assert personas.load_persona(tmp_path, ids[0]) == original


def test_catalog_filter_matches_public_validation_and_rejects_corruption(tmp_path):
    _seed(tmp_path, count=3, product="browser-core", major=153)
    kwargs = dict(engine="chromium", product="browser-core", major=153, device_class="desktop")
    documents = personas.list_personas(tmp_path)
    expected = [p["id"] for p in documents if personas.persona_compatible(p, **kwargs)]
    ids, active = personas.compatible_persona_catalog(tmp_path, **kwargs)
    assert ids == expected and active == len(documents)
    documents[0]["kernel"]["product"] = "chrome"
    with pytest.raises(ContractError, match="integrity"):
        personas.persona_compatible(documents[0], **kwargs)
    (tmp_path / "personas" / "catalog" / "unrelated.json").write_bytes(b'{}\n')
    with pytest.raises(ContractError, match="valid managed document"):
        personas.compatible_persona_catalog(tmp_path, **kwargs)
