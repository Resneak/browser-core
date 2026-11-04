# Setup

## Use the Windows runtime

1. Download `browser-core-runtime-windows-x64.zip` and `SHA256SUMS.txt` from the same GitHub Release.
2. Compare the archive's `Get-FileHash -Algorithm SHA256` result with the published checksum.
3. Extract it to a new short directory, such as `C:\bc-runtime`. Keep the complete runtime folder together.
4. Run the repository's preparation script. It removes Windows download blocking and grants the normal Chromium sandbox read and execute access to this runtime directory.

```powershell
.\scripts\prepare-runtime.ps1 -RuntimeDirectory C:\bc-runtime
```

Do not use `--no-sandbox` to work around an access problem. Choose a folder your account can manage; the script may require an administrator if that folder has restrictive permissions.

Install the Python package as described in the README, then verify the runtime:

```powershell
browser-core doctor --executable C:\bc-runtime\chrome.exe
```

`runtime_verified: true` means the core browser files match this package's pinned resources. It does not prove successful browser startup or complete capture. The first actual recording checks startup too.

## Run the included demo

In one terminal, serve the owned example locally:

```powershell
python -m http.server 8000 --bind 127.0.0.1 --directory examples/runtime-demo
```

In another terminal, with the virtual environment activated:

```powershell
browser-core record http://127.0.0.1:8000/ --workspace C:\bc-data --executable C:\bc-runtime\chrome.exe --out C:\bc-data\demo --seconds 10
```

Read `C:\bc-data\demo-calls.md`, then open the full `report.html`. The output directory must be new. Every run uses a fresh retained profile, so it does not use your daily browser's login state.

## Query a saved recording

Use the matching full browser executable as the reader, not a standalone trace processor:

```powershell
browser-core trace evidence-query --bundle C:\bc-data\demo\recording.bcevidence --reader-executable C:\bc-runtime\chrome.exe --metadata-version 2 --api HTMLCanvasElement.toDataURL --limit 25
```

Use exact API names and identifiers from the recording. The call index references the generated code event by sequence number; find that event in `events.jsonl` to inspect the recorded link.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| Runtime verification fails | Check that the Python package and runtime came from the same source release and that the browser files are intact. |
| Browser refuses to start | Run the preparation script, keep all runtime files together, and check the workspace permissions. |
| Collection fails | Keep the failure receipt. Choose a fresh output directory for a retry; never interpret the failure as an absence of page activity. |
| An API is missing | Check capture health and the full recording. A missing row is not evidence that the API never ran. |
| A caller is unresolved | Retain that uncertainty. Do not join script numbers across processes or contexts. |

Large recordings take longer to validate. The initial pass reads the recording before producing trustworthy queries. The runtime is pinned for reproducibility and is not a regularly updated general browsing distribution.
