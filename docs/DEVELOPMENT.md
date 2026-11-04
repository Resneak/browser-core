# Development

## Python tooling

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests/test_record_entry.py tests/test_contracts.py tests/test_trace.py tests/test_session_query.py
```

The full inherited suite includes host specific and monorepo integration checks. Some documentation and sibling evaluator checks require files outside this standalone export. Do not report a full suite pass from the focused command above.

## Native browser build

The Windows scripts pin Chromium and depot_tools revisions in `upstream.json`. Chromium requires its own supported Windows compiler and SDK toolchain, substantial disk space and a long initial build. Follow Chromium's upstream Windows build prerequisites before starting.

Choose a short NTFS workspace outside the repository:

```powershell
$env:BROWSER_CORE_WORKSPACE = "C:\bc-build"
.\scripts\bootstrap.ps1
.\scripts\apply-patches.ps1
.\scripts\build.ps1
```

Do not modify the ordered native patches without a fresh build and qualification. The Python resource manifest and browser build receipt must agree. The checked in patch sequence includes legacy identity experiments; see the architecture note.

## Snapshot provenance

The original source export was taken from commit `29fc6498202b8d1ac4079300e62ba7bd72fcee36` of the author's private research repository. This public repository starts with a fresh history and excludes private lab captures, accounts, profiles, build outputs and unrelated research. The convenience recorder, sample and public documentation were added for this standalone edition.
