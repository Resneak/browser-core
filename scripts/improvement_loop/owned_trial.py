"""One loopback benchmark trial with a single AgentProcess browser owner.

The imported v2 handler is used only to serve the synthetic task and log
metadata. Its legacy launch_evaluation function is never called.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from browser_core.agent_process import AgentProcess


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def publish(path: Path, value: dict) -> None:
    staging = path.with_name(path.name + ".tmp-" + secrets.token_hex(4))
    staging.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(staging, path)


def load_server(harness: Path, hook_path: Path):
    sys.path.insert(0, str(harness))
    try:
        from bench_session import Log, handler
    finally:
        sys.path.pop(0)
    spec = importlib.util.spec_from_file_location("tier1_task_hook", hook_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return Log, handler, module.handle


async def run(args) -> None:
    run_dir = args.run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "control").mkdir()
    (run_dir / "work").mkdir()
    task = args.task.resolve(strict=True)
    routes = json.loads((task / "routes.json").read_text(encoding="utf-8"))
    Log, handler, hook = load_server(args.bench_harness.resolve(strict=True),
                                     args.hook.resolve(strict=True))
    server_log = Log(run_dir / "server.jsonl")
    server = ThreadingHTTPServer(("127.0.0.1", 0),
        handler(task, routes, server_log, hook, {}))
    port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    info = {"schema": "browser-eval.owned-trial/1", "trial_id": run_dir.name,
            "task_id": args.task_id,
            "arm": args.arm, "task_url": f"http://127.0.0.1:{port}/index.html",
            "created_at": utc(), "launches": [],
            "tools": {"cli": str(args.cli), "python": str(args.python),
                      "node": str(args.node),
                      "devtools": str(args.devtools)}}
    owner = None

    async def close_owner():
        nonlocal owner
        if owner is None:
            return None
        await owner.close()
        state = owner.snapshot()
        receipt = {key: state.get(key) for key in
                   ("succeeded", "creator_exit_observed", "connection_closed")}
        if not all(receipt.values()):
            raise RuntimeError("AgentProcess owner close incomplete")
        owner = None
        return receipt

    async def start_owner(number: int):
        nonlocal owner
        workspace = args.workspace_root / f"ws-{args.profile_prefix}-{number}"
        workspace.mkdir(parents=True, exist_ok=False)
        temp = workspace / ("tmp-" + secrets.token_hex(4))
        temp.mkdir()
        os.environ["TEMP"] = str(temp)
        os.environ["TMP"] = str(temp)
        profile = f"{args.profile_prefix}{number}"
        command = [str(args.cli), "research", profile, "--agent-control",
                   "--metadata-only", "--workspace", str(workspace),
                   "--executable", str(args.runtime), "--headless"]
        candidate = AgentProcess(command, cwd=args.workspace_root,
                                 workspace=workspace, profile_id=profile)
        owner = candidate
        await owner.open()
        if owner.snapshot().get("ready_for_start") is not True:
            raise RuntimeError("AgentProcess did not become ready")
        await owner.start()
        ready = owner.snapshot()["channel"]["ready"]
        session_file = Path(ready["session_file"])
        session = json.loads(session_file.read_text(encoding="utf-8"))
        launch = {"number": number, "run_id": ready["run_id"],
                  "session_file": str(session_file),
                  "cdp_endpoint": session["automation"]["cdp_endpoint"],
                  "managed_target_url": session["automation"]["managed_target_url"],
                  "at": utc()}
        info["launches"].append(launch)
        publish(run_dir / "run-info.json", info)
        return launch

    def snapshot(label: str, started: float):
        claims = run_dir / "work" / "claims.json"
        row = {"label": label, "elapsed_minutes": round((time.monotonic() - started) / 60, 3),
               "at": utc(), "valid_json": False}
        if claims.is_file():
            try:
                body = claims.read_bytes()
                parsed = json.loads(body)
                if isinstance(parsed, dict) and isinstance(parsed.get("claims"), list):
                    dest = run_dir / "claims-snapshots"
                    dest.mkdir(exist_ok=True)
                    (dest / f"{label}.json").write_bytes(body)
                    row["valid_json"] = True
                    row["claims_count"] = len(parsed["claims"])
            except (ValueError, OSError):
                pass
        with (run_dir / "snapshot-index.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row) + "\n")

    final = "error"
    started = time.monotonic()
    try:
        await start_owner(1)
        next_snapshot = 5
        handled = set()
        while time.monotonic() - started < args.limit_minutes * 60:
            elapsed = (time.monotonic() - started) / 60
            if next_snapshot <= args.limit_minutes and elapsed >= next_snapshot:
                snapshot(f"t{next_snapshot:02d}", started)
                next_snapshot += 5
            request_file = run_dir / "control" / "request.json"
            if request_file.is_file():
                try:
                    request = json.loads(request_file.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    request = {}
                request_id = request.get("id")
                if isinstance(request_id, str) and request_id not in handled:
                    handled.add(request_id)
                    command = request.get("cmd")
                    response = {"id": request_id, "cmd": command, "at": utc()}
                    if command == "restart":
                        response["closed"] = await close_owner()
                        response["launch"] = await start_owner(len(info["launches"]) + 1)
                    elif command == "stop":
                        final = "requested"
                    else:
                        response["error"] = "unknown-control-command"
                    publish(run_dir / "control" / f"response-{request_id}.json", response)
                    if final == "requested":
                        break
            await asyncio.sleep(0.2)
        else:
            final = "time-limit"
    finally:
        snapshot("final", started)
        try:
            info["final_close"] = await close_owner()
        finally:
            info["final_reason"] = final
            info["finished_at"] = utc()
            publish(run_dir / "run-info.json", info)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--arm", choices=("A_base", "A_new"), required=True)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--hook", type=Path, required=True)
    parser.add_argument("--bench-harness", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--devtools", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--profile-prefix", required=True)
    parser.add_argument("--limit-minutes", type=float, default=40)
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
