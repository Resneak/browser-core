"""Content-addressed cache of validated, value-free metadata populations.

Why this exists
---------------
Every metadata query used to re-export the whole recording with
trace_processor and re-run the full population validator, even though a
stopped recording never changes. On a 39 MB recording that was ~150 s per
query, for a five-event answer. Agents in the v2 benchmark recovered most
runtime-hidden facts only when they completed ten or more detailed queries,
so per-query latency directly caps what an agent can learn.

What is cached, and why it is equivalent
----------------------------------------
An entry is written only after a fresh decode has passed *every*
population-wide check used by any metadata query mode (exporter validation,
the normalized-trace validator, row projection and inventory identity
checks) and the recording has been confirmed value-free. The key binds the
exact snapshot SHA-256, run ID, Chromium revision, reader runtime identity,
package version and this format version, so a different recording, reader
or package can never reuse an entry. On a hit both cached files are
re-hashed against the manifest before use; a mismatch discards the entry
and the caller falls back to a fresh decode. Callers still apply their
exact Python filter to every candidate row, so the SQL index is only a
superset prefilter and cannot change results.

Trust boundary: entries live in the current user's local application data
(or BROWSER_CORE_METADATA_CACHE). Anyone who can write there can also
modify the installed package, so the cache adds no new trust assumption.
Set BROWSER_CORE_METADATA_CACHE=off to disable it.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from typing import Callable, Iterator

from .control_files import canonical_json_bytes

FORMAT = 'browser-core.population-cache/1'
ENV = 'BROWSER_CORE_METADATA_CACHE'
MAX_ENTRIES = 24
MAX_TOTAL_BYTES = 6 * 1024 * 1024 * 1024
_HASH_CHUNK = 4 * 1024 * 1024
_CACHEABLE_PHASES = frozenset({'finalized-recording', 'recovered-prefix',
                               'interrupted-recording', 'limited-recording'})


def cache_root() -> Path | None:
    """Return the cache directory, or None when caching is disabled."""
    configured = os.environ.get(ENV)
    if configured is not None:
        if configured.strip().lower() in {'', 'off', '0', 'false', 'no'}:
            return None
        root = Path(configured)
    else:
        base = os.environ.get('LOCALAPPDATA') or os.environ.get('XDG_CACHE_HOME')
        if not base:
            base = str(Path.home() / '.cache')
        root = Path(base) / 'browser-core' / 'metadata-cache'
    if not root.is_absolute():
        return None
    return root


def _plain_directory(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not (
        getattr(metadata, 'st_file_attributes', 0) & 0x400)


def cache_key(*, phase: str, snapshot_sha256: str, run_id: str, revision: str,
              reader_runtime: object, package_version: str) -> str | None:
    if phase not in _CACHEABLE_PHASES:
        return None
    material = {'format': FORMAT, 'snapshot_sha256': snapshot_sha256, 'run_id': run_id,
                'chromium_revision': revision, 'reader_runtime': reader_runtime,
                'package_version': package_version}
    try:
        return hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    except Exception:
        return None


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _script_number(event: dict) -> str:
    script = (event.get('execution') or {}).get('script_id') or ''
    return script.rsplit(':', 1)[-1] if script.startswith('v8:') else ''


class CachedPopulation:
    """A verified cache entry: highwater, health and filtered event access."""

    def __init__(self, directory: Path, manifest: dict):
        self.directory = directory
        self.manifest = manifest
        self.highwater = manifest['highwater']
        self.health = manifest['health']

    def _connect(self) -> sqlite3.Connection:
        uri = (self.directory / 'index.sqlite3').resolve().as_uri() + '?mode=ro'
        return sqlite3.connect(uri, uri=True)

    def events(self, filters: dict | None) -> Iterator[dict]:
        """Yield candidate events in original file order.

        `filters=None` yields the whole population. Otherwise the SQL
        prefilter uses only exact name, process and time bounds; the caller's
        own matcher remains the authority on what matches.
        """
        clauses, params = [], []
        if filters is not None:
            apis = list(filters.get('apis') or ())
            if apis:
                clauses.append('name IN (%s)' % ','.join('?' * len(apis)))
                params.extend(apis)
            if filters.get('script'):
                clauses.append('script_number = ?')
                params.append(filters['script'])
            selector = filters.get('portable_context')
            if selector:
                clauses.append('pid = ?')
                params.append(selector['pid'])
            if filters.get('start_ns'):
                clauses.append('ts >= ?')
                params.append(int(filters['start_ns']))
            if filters.get('end_ns'):
                clauses.append('ts <= ?')
                params.append(int(filters['end_ns']))
        sql = 'SELECT offset, length FROM events'
        if clauses:
            sql += ' WHERE ' + ' AND '.join(clauses)
        sql += ' ORDER BY offset'
        connection = self._connect()
        try:
            rows = connection.execute(sql, params)
            with (self.directory / 'events.jsonl').open('rb') as handle:
                for offset, length in rows:
                    handle.seek(offset)
                    line = handle.read(length)
                    if len(line) != length:
                        raise ValueError('population cache line is truncated')
                    yield json.loads(line)
        finally:
            connection.close()


def load(key: str | None) -> CachedPopulation | None:
    """Return a verified entry, or None (missing, disabled or corrupt)."""
    root = cache_root()
    if key is None or root is None or not _plain_directory(root):
        return None
    directory = root / key
    if not _plain_directory(directory):
        return None
    try:
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        if manifest.get('format') != FORMAT or manifest.get('key') != key:
            raise ValueError('population cache manifest mismatch')
        for name in ('events.jsonl', 'index.sqlite3'):
            digest, size = _sha256_file(directory / name)
            expected = manifest['files'][name]
            if digest != expected['sha256'] or size != expected['bytes']:
                raise ValueError('population cache file changed')
        if type(manifest.get('highwater')) is not int or not isinstance(manifest.get('health'), dict):
            raise ValueError('population cache manifest is invalid')
    except (OSError, ValueError, KeyError, TypeError):
        shutil.rmtree(directory, ignore_errors=True)
        return None
    try:
        os.utime(directory / 'manifest.json')
    except OSError:
        pass
    return CachedPopulation(directory, manifest)


def store(key: str | None, events_path: Path, *, health: dict,
          validate: Callable[[dict], None]) -> bool:
    """Index an already-validated normalized events file. Never raises.

    `validate` is applied to every event so the entry is valid for every
    query mode, not just the one that happened to build it. Any failure
    leaves no entry behind.
    """
    root = cache_root()
    if key is None or root is None:
        return False
    staging = None
    try:
        root.mkdir(parents=True, exist_ok=True)
        if not _plain_directory(root):
            return False
        final = root / key
        if final.exists():
            return True
        staging = root / f'.staging-{uuid.uuid4().hex}'
        staging.mkdir()
        shutil.copyfile(events_path, staging / 'events.jsonl')
        connection = sqlite3.connect(staging / 'index.sqlite3')
        highwater = None
        count = 0
        try:
            connection.execute('CREATE TABLE events (offset INTEGER PRIMARY KEY, length INTEGER NOT NULL,'
                               ' seq INTEGER NOT NULL, ts INTEGER NOT NULL, name TEXT NOT NULL,'
                               ' pid TEXT NOT NULL, script_number TEXT NOT NULL)')
            batch = []
            offset = 0
            with (staging / 'events.jsonl').open('rb') as handle:
                for line in handle:
                    length = len(line)
                    body = line.rstrip(b'\r\n')
                    if body.strip():
                        event = json.loads(body)
                        validate(event)
                        highwater = event['seq']
                        batch.append((offset, len(body), event['seq'], event['ts_monotonic_ns'],
                                      event['event']['name'], str(event['process']['pid']),
                                      _script_number(event)))
                        count += 1
                        if len(batch) >= 5000:
                            connection.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?)', batch)
                            batch.clear()
                    offset += length
            if batch:
                connection.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?)', batch)
            connection.execute('CREATE INDEX events_name ON events(name, offset)')
            connection.execute('CREATE INDEX events_pid ON events(pid, offset)')
            connection.execute('CREATE INDEX events_script ON events(script_number, offset)')
            connection.commit()
        finally:
            connection.close()
        files = {}
        for name in ('events.jsonl', 'index.sqlite3'):
            digest, size = _sha256_file(staging / name)
            files[name] = {'sha256': digest, 'bytes': size}
        manifest = {'format': FORMAT, 'key': key, 'events': count,
                    'highwater': highwater if highwater is not None else 0,
                    'health': health, 'files': files,
                    'created_unix': int(time.time())}
        (staging / 'manifest.json').write_bytes(canonical_json_bytes(manifest))
        try:
            os.replace(staging, final)
        except OSError:
            return final.exists()
        staging = None
        _prune(root)
        return True
    except Exception:
        return False
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _prune(root: Path) -> None:
    entries = []
    for child in root.iterdir():
        if child.name.startswith('.staging-'):
            try:
                if time.time() - child.stat().st_mtime > 3600:
                    shutil.rmtree(child, ignore_errors=True)
            except OSError:
                pass
            continue
        manifest = child / 'manifest.json'
        try:
            used = manifest.stat().st_mtime
            size = sum(item.stat().st_size for item in child.iterdir())
        except OSError:
            continue
        entries.append((used, size, child))
    entries.sort(reverse=True)
    total = 0
    for index, (_used, size, child) in enumerate(entries):
        total += size
        if index >= MAX_ENTRIES or total > MAX_TOTAL_BYTES:
            shutil.rmtree(child, ignore_errors=True)
