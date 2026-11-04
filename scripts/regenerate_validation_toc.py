"""Regenerate the contents block at the top of `docs/VALIDATION.md`.

Why this exists
---------------
`VALIDATION.md` is the canonical evidence ledger and has to stay complete: it is
286 KB across 95 sections. That is roughly 71,500 tokens, larger than many working
contexts, and it had no contents block — so an operator asking "has X been
validated?" could either read the whole thing or grep blindly and hope the wording
matched.

A human scrolls a long document cheaply. The intended operator here is an agent
for whom every line read is spent context, so navigation is not a nicety: without
it the ledger is effectively write-only.

This regenerates the block rather than hand-maintaining it, because a stale
contents list is worse than none — it sends the reader to the wrong line with
confidence. `tests/test_validation_toc.py` fails when the file drifts from its
block, so the two cannot silently diverge.

Content below the marker is never touched; this only rewrites the navigation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from browser_core.control_files import (  # noqa: E402
    BoundedControlSnapshot,
    read_bounded_control_snapshot_result,
    replace_bytes_conditionally_result,
)
from browser_core.errors import ContractError  # noqa: E402

LEDGER = ROOT / "docs" / "VALIDATION.md"
MAX_VALIDATION_LEDGER_BYTES = 16 * 1024 * 1024

BEGIN = "<!-- BEGIN GENERATED CONTENTS -->"
END = "<!-- END GENERATED CONTENTS -->"

PREAMBLE = """\
> Generated navigation — do not edit by hand. Regenerate with
> `python scripts/regenerate_validation_toc.py`; `tests/test_validation_toc.py`
> fails if this block drifts from the headings below it. Line numbers are for
> jumping directly rather than reading the whole ledger, which is ~71k tokens.
"""


def _slug(title: str) -> str:
    """GitHub-style anchor slug."""
    s = title.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"[\s_]+", "-", s).strip("-")


def build_contents(text: str, *, offset: int = 0) -> str:
    """Build the contents block for a ledger body (body = text after the H1).

    ``offset`` is added to every line number. It matters because inserting this
    block shifts everything below it: without the offset the list points ~106
    lines above each real heading, which is worse than having no list at all —
    it sends the reader somewhere wrong with confidence. :func:`main` resolves it
    in two passes, building once to learn the block's own height and again with
    that height applied.
    """
    lines = text.splitlines()
    rows: list[str] = []
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^(#{2,3})\s+(.*)$", line)
        if not match:
            continue
        depth, title = len(match.group(1)), match.group(2).strip()
        indent = "  " * (depth - 2)
        rows.append(f"{indent}- [{title}](#{_slug(title)}) — L{index + offset}")
    body = "\n".join(rows)
    return f"{BEGIN}\n\n## Contents\n\n{PREAMBLE}\n{body}\n\n{END}"


def _ledger_snapshot(path: Path) -> tuple[BoundedControlSnapshot, str, str]:
    if not isinstance(path, Path):
        raise ContractError("validation ledger path must be a Path")
    snapshot = read_bounded_control_snapshot_result(
        path,
        maximum=MAX_VALIDATION_LEDGER_BYTES,
        label="validation ledger",
        require_single_link=True,
    )
    if snapshot.state != "complete" or snapshot.body is None or snapshot.identity is None:
        raise ContractError("validation ledger is not a complete stable file")
    try:
        text = snapshot.body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ContractError("validation ledger is not valid UTF-8") from None
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf:
        raise ContractError("validation ledger has mixed or bare-CR line endings")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    if text.count(BEGIN) != text.count(END) or text.count(BEGIN) > 1:
        raise ContractError("validation ledger contents markers are invalid")
    if BEGIN in text and text.index(BEGIN) >= text.index(END):
        raise ContractError("validation ledger contents markers are out of order")
    return snapshot, text, newline


def current_and_expected(path: Path = LEDGER) -> tuple[str | None, str]:
    """Return (existing block or None, expected block) for the ledger."""
    _snapshot, text, _newline = _ledger_snapshot(path)
    existing = None
    if BEGIN in text and END in text:
        start = text.index(BEGIN)
        stop = text.index(END) + len(END)
        existing = text[start:stop]
        # Headings must be counted from the document *without* the block, so the
        # line numbers a reader sees match the file they will actually open.
        stripped = text[:start] + text[stop:].lstrip("\n")
        expected = _build_with_offset(stripped)
    else:
        expected = _build_with_offset(text)
    return existing, expected


def _build_with_offset(body: str) -> str:
    """Two-pass build: measure the block's own height, then apply it as offset.

    The block is inserted after the H1, so every heading below it moves down by
    the block's line count plus the blank line that follows. Building once to
    measure and again to emit is the simplest way to make the printed numbers
    match the file the reader will actually open.
    """
    probe = build_contents(body)
    shift = len(probe.splitlines()) + 1
    return build_contents(body, offset=shift)


def regenerate(path: Path = LEDGER) -> tuple[int, int]:
    """Conditionally replace exactly the stable ledger population just read."""
    snapshot, text, newline = _ledger_snapshot(path)

    if BEGIN in text and END in text:
        start = text.index(BEGIN)
        stop = text.index(END) + len(END)
        body = text[:start] + text[stop:].lstrip("\n")
    else:
        body = text

    lines = body.splitlines()
    # Insert directly after the H1 title so the ledger still opens with its name.
    insert_at = 1 if lines and lines[0].startswith("# ") else 0
    head = "\n".join(lines[:insert_at])
    rest = "\n".join(lines[insert_at:])

    block = _build_with_offset(body)
    rebuilt = f"{head}\n\n{block}\n{rest}\n" if head else f"{block}\n\n{rest}\n"
    rebuilt = re.sub(r"\n{4,}", "\n\n\n", rebuilt)

    try:
        serialized = rebuilt if newline == "\n" else rebuilt.replace("\n", newline)
        rebuilt_body = serialized.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ContractError("rebuilt validation ledger is not valid UTF-8") from None
    if len(rebuilt_body) > MAX_VALIDATION_LEDGER_BYTES:
        raise ContractError("rebuilt validation ledger exceeds the byte limit")
    if rebuilt_body != snapshot.body:
        replace_bytes_conditionally_result(
            path,
            rebuilt_body,
            expected_body=snapshot.body,
            expected_identity=snapshot.identity,
            maximum=MAX_VALIDATION_LEDGER_BYTES,
            label="validation ledger",
        )
    entries = block.count("\n- ") + block.count("\n  - ")
    return entries, len(rebuilt)


def main() -> int:
    entries, characters = regenerate()
    print(f"regenerated contents: {entries} entries, ledger now {characters:,} chars")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
