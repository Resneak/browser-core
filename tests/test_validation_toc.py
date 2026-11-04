"""The evidence ledger's contents block must stay in sync with its headings.

`docs/VALIDATION.md` is ~298 KB / ~74k tokens across 94 sections — larger than
many working contexts, so its contents block is the only affordable way in. A
*stale* block is worse than none: it sends the reader to a confidently wrong line
number. This fails the suite when the ledger and its block drift apart.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from browser_core.errors import ContractError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import regenerate_validation_toc as toc_module  # noqa: E402
from regenerate_validation_toc import (  # noqa: E402
    BEGIN,
    END,
    LEDGER,
    build_contents,
    current_and_expected,
    regenerate,
)


def test_regenerate_publishes_a_current_block_and_then_is_idempotent(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "VALIDATION.md"
    ledger.write_text("# Validation\n\n## Alpha\n\ntext\n", encoding="utf-8")
    entries, characters = regenerate(ledger)
    assert entries == 1
    assert characters == len(ledger.read_text(encoding="utf-8"))
    existing, expected = current_and_expected(ledger)
    assert existing == expected
    before = ledger.stat()
    regenerate(ledger)
    after = ledger.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )


def test_regenerate_rejects_ambiguous_contents_markers(tmp_path: Path) -> None:
    ledger = tmp_path / "VALIDATION.md"
    ledger.write_text(f"# Validation\n{BEGIN}\n## Alpha\n", encoding="utf-8")
    with pytest.raises(ContractError, match="markers"):
        regenerate(ledger)


def test_regenerate_preserves_a_competing_edit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "VALIDATION.md"
    ledger.write_text("# Validation\n\n## Alpha\n", encoding="utf-8")
    competitor = "# Competing edit\n\n## Private\n\nkeep me\n"
    real_replace = toc_module.replace_bytes_conditionally_result

    def inject_edit(path: Path, body: bytes, **kwargs):  # type: ignore[no-untyped-def]
        path.write_text(competitor, encoding="utf-8")
        return real_replace(path, body, **kwargs)

    monkeypatch.setattr(toc_module, "replace_bytes_conditionally_result", inject_edit)
    with pytest.raises(ContractError, match="changed before transition"):
        regenerate(ledger)
    assert ledger.read_text(encoding="utf-8") == competitor


def test_ledger_has_a_generated_contents_block() -> None:
    text = LEDGER.read_text(encoding="utf-8")
    assert BEGIN in text and END in text, (
        "VALIDATION.md has no generated contents block; run "
        "`python scripts/regenerate_validation_toc.py`"
    )


def test_contents_block_is_current() -> None:
    existing, expected = current_and_expected()
    assert existing == expected, (
        "VALIDATION.md contents block is stale; regenerate with "
        "`python scripts/regenerate_validation_toc.py`"
    )


def test_every_line_number_resolves_to_its_heading() -> None:
    """The property that actually matters: the numbers must be usable.

    Guards the bug this shipped with — line numbers were computed before the
    block was inserted, so all 94 pointed ~106 lines above their real heading.
    """
    lines = LEDGER.read_text(encoding="utf-8").splitlines()
    wrong: list[str] = []
    checked = 0
    for line in lines:
        match = re.match(r"\s*- \[(.+?)\]\(#.*?\)\s+.\s+L(\d+)$", line)
        if not match:
            continue
        title, number = match.group(1), int(match.group(2))
        checked += 1
        if number > len(lines) or title not in lines[number - 1]:
            wrong.append(f"{title!r} -> L{number}")
    assert checked > 50, f"only found {checked} contents entries; parser may be broken"
    assert not wrong, f"{len(wrong)} of {checked} line numbers are wrong: {wrong[:3]}"


def test_every_heading_appears_in_the_contents() -> None:
    text = LEDGER.read_text(encoding="utf-8")
    start, stop = text.index(BEGIN), text.index(END) + len(END)
    body = text[:start] + text[stop:]
    headings = [
        m.group(2).strip()
        for m in re.finditer(r"^(#{2,3})\s+(.*)$", body, re.M)
    ]
    block = text[start:stop]
    missing = [h for h in headings if f"[{h}]" not in block]
    assert not missing, f"headings absent from contents: {missing[:5]}"


def test_contents_does_not_index_itself() -> None:
    """The `## Contents` heading must not appear as one of its own entries."""
    text = LEDGER.read_text(encoding="utf-8")
    block = text[text.index(BEGIN) : text.index(END) + len(END)]
    assert "[Contents](#contents)" not in block


@pytest.mark.parametrize(
    "title,expected",
    [
        ("Final source and native build pin", "final-source-and-native-build-pin"),
        ("Native tracing: 0.4 baseline", "native-tracing-04-baseline"),
        ("WebRE 0.83.0 request source-cohort", "webre-0830-request-source-cohort"),
    ],
)
def test_anchor_slugs_match_github_style(title, expected) -> None:
    from regenerate_validation_toc import _slug

    assert _slug(title) == expected


def test_offset_shifts_every_entry() -> None:
    body = "# T\n\n## Alpha\n\ntext\n\n## Beta\n"
    plain = build_contents(body)
    shifted = build_contents(body, offset=10)
    assert "— L3" in plain and "— L13" in shifted
